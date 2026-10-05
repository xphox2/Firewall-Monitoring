package database

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
	"unicode/utf8"

	"firewall-mon/internal/models"
	"firewall-mon/internal/normalize"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Writers for the v72 normalized event tables (Phase 1, S-3). The ingest
// wiring that calls them is S-4; the 30-day backfill job is S-5. Both go
// through the same two steps: NetEventFromEvent / SecEventFromEvent turn a
// normalize.Event into the table row (one mapping, shared by the COPY path and
// the GORM fallback, so the SQLite lane tests the same mapping production
// writes), then SaveNetEvents / SaveSecEvents persist a batch.

// netEventExtraMax caps the `extra` JSON object (roadmap §1.2: "capped ~1 KB").
// Keys are added in sorted order until the budget is spent, so what survives
// is deterministic.
const netEventExtraMax = 1024

// NetEventFromEvent maps a network-class Event to its net_events row. rawID /
// rawTS name the syslog_messages row the event came from; rawID 0 means
// "none" (both provenance columns NULL). NULL discipline: a nil pointer or an
// empty string on the Event is NULL in the row.
func NetEventFromEvent(ev *normalize.Event, rawID int64, rawTS time.Time) models.NetEvent {
	row := models.NetEvent{
		Ts:            ev.Ts,
		DeviceID:      ev.DeviceID,
		ProbeID:       ev.ProbeID,
		Activity:      int16(ev.Activity),
		Action:        int16(ev.Action),
		VendorEventID: nullStr(ev.VendorEventID),

		SrcIP:     nullIP(ev.SrcIP),
		SrcPort:   ev.SrcPort,
		DstIP:     nullIP(ev.DstIP),
		DstPort:   ev.DstPort,
		Proto:     ev.Proto,
		SrcMAC:    nullMAC(ev.SrcMAC),
		DstMAC:    nullMAC(ev.DstMAC),
		SrcIf:     nullStr(ev.SrcIf),
		DstIf:     nullStr(ev.DstIf),
		SrcZone:   nullStr(ev.SrcZone),
		DstZone:   nullStr(ev.DstZone),
		SrcRole:   nullRole(ev.SrcRole),
		DstRole:   nullRole(ev.DstRole),
		Direction: nullDirection(ev.Direction),

		RuleKey:   nullStr(ev.RuleKey),
		RuleUID:   nullStr(ev.RuleUID),
		RuleID:    ev.RuleID,
		RuleName:  nullStr(ev.RuleName),
		RuleIndex: ev.RuleIndex,
		Ruleset:   nullStr(ev.Ruleset),

		UserName:    nullStr(ev.User),
		UserGroup:   nullStr(ev.Group),
		App:         nullStr(ev.App),
		AppCat:      nullStr(ev.AppCat),
		AppRisk:     ev.AppRisk,
		DevType:     nullStr(ev.DevType),
		OSName:      nullStr(ev.OSName),
		SrcHostname: nullStr(ev.SrcHostname),

		BytesOut:   ev.BytesOut,
		BytesIn:    ev.BytesIn,
		PktsOut:    ev.PktsOut,
		PktsIn:     ev.PktsIn,
		DurationMS: ev.DurationMS,
		SessionID:  nullStr(ev.SessionID),

		NatSrcIP:   nullIP(ev.NatSrcIP),
		NatSrcPort: ev.NatSrcPort,
		NatDstIP:   nullIP(ev.NatDstIP),
		NatDstPort: ev.NatDstPort,

		SrcCountry: nullStr(ev.SrcCountry),
		DstCountry: nullStr(ev.DstCountry),
		ThreatFlag: ev.ThreatFlag,

		URLHost:  nullStr(ev.URLHost),
		URLPath:  nullStr(ev.URLPath),
		DNSQName: nullStr(ev.DNSQName),
		DNSQType: ev.DNSQType,
		WebCat:   nullStr(ev.WebCat),

		Extra: extraJSON(ev.Extra),
	}
	row.RawID, row.RawTS = provenance(rawID, rawTS)
	return row
}

// SecEventFromEvent maps an Event of any class but network to its sec_events
// row. Same contract as NetEventFromEvent; Message is capped at
// models.SecEventMessageMax bytes on a rune boundary.
func SecEventFromEvent(ev *normalize.Event, rawID int64, rawTS time.Time) models.SecEvent {
	row := models.SecEvent{
		Ts:            ev.Ts,
		DeviceID:      ev.DeviceID,
		ProbeID:       ev.ProbeID,
		Class:         int16(ev.Class),
		Activity:      int16(ev.Activity),
		Action:        int16(ev.Action),
		Severity:      ev.Severity,
		VendorEventID: nullStr(ev.VendorEventID),

		SrcIP:       nullIP(ev.SrcIP),
		SrcPort:     ev.SrcPort,
		DstIP:       nullIP(ev.DstIP),
		DstPort:     ev.DstPort,
		Proto:       ev.Proto,
		SrcMAC:      nullMAC(ev.SrcMAC),
		UserName:    nullStr(ev.User),
		UserGroup:   nullStr(ev.Group),
		SrcHostname: nullStr(ev.SrcHostname),

		AdminUser:   nullStr(ev.AdminUser),
		AdminSrcIP:  nullIPString(ev.AdminSrcIP),
		AdminMethod: nullStr(ev.AdminMethod),

		SigID:     nullStr(ev.SigID),
		SigName:   nullStr(ev.SigName),
		ThreatCat: nullStr(ev.ThreatCat),
		FileHash:  nullStr(ev.FileHash),
		URLHost:   nullStr(ev.URLHost),

		TunnelName: nullStr(ev.TunnelName),
		TunnelType: nullStr(ev.TunnelType),
		TunnelPeer: nullIP(ev.TunnelPeer),

		ConfigPath: nullStr(ev.ConfigPath),
		ConfigObj:  nullStr(ev.ConfigObj),
		ConfigOld:  nullStr(ev.ConfigOld),
		ConfigNew:  nullStr(ev.ConfigNew),

		WANName:     nullStr(ev.WANName),
		MetricName:  nullStr(ev.MetricName),
		MetricValue: ev.MetricValue,
		Message:     nullStr(truncateUTF8(ev.Message, models.SecEventMessageMax)),

		Extra: extraJSON(ev.Extra),
	}
	row.RawID, row.RawTS = provenance(rawID, rawTS)
	return row
}

// FwRuleFromEvent is the fw_rules catalog row an event with a rule identity
// contributes (Source = log): ok is false when the event names no rule.
func FwRuleFromEvent(ev *normalize.Event, seen time.Time) (models.FwRule, bool) {
	if ev.RuleKey == "" {
		return models.FwRule{}, false
	}
	return models.FwRule{
		DeviceID:  ev.DeviceID,
		RuleKey:   ev.RuleKey,
		RuleUID:   nullStr(ev.RuleUID),
		RuleID:    ev.RuleID,
		RuleName:  nullStr(ev.RuleName),
		RuleIndex: ev.RuleIndex,
		Ruleset:   nullStr(ev.Ruleset),
		Source:    models.FwRuleSourceLog,
		FirstSeen: seen,
		LastSeen:  seen,
	}, true
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullIP(ip net.IP) *string {
	if ip == nil {
		return nil
	}
	s := ip.String()
	return &s
}

// nullIPString is nullIP for an address the Event keeps as text
// (AdminSrcIP): only a parseable address is stored in an inet column.
func nullIPString(s string) *string {
	if s == "" {
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	s = a.WithZone("").String()
	return &s
}

func nullMAC(m net.HardwareAddr) *string {
	if m == nil {
		return nil
	}
	s := m.String()
	return &s
}

func nullRole(r *normalize.Role) *int16 {
	if r == nil {
		return nil
	}
	v := int16(*r)
	return &v
}

func nullDirection(d *normalize.Direction) *int16 {
	if d == nil {
		return nil
	}
	v := int16(*d)
	return &v
}

func provenance(rawID int64, rawTS time.Time) (*int64, *time.Time) {
	if rawID == 0 {
		return nil, nil
	}
	return &rawID, &rawTS
}

// extraJSON renders the vendor leftovers as a JSON object of at most
// netEventExtraMax bytes (keys in sorted order, the first ones that fit), or
// NULL when there are none.
func extraJSON(extra map[string]string) *string {
	if len(extra) == 0 {
		return nil
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kept := make(map[string]string, len(extra))
	size := 2 // the braces
	for _, k := range keys {
		// Each member costs roughly `"k":"v",` — an upper bound on the quoted
		// forms is good enough for a soft cap.
		cost := len(k) + len(extra[k]) + 6
		if size+cost > netEventExtraMax {
			break
		}
		kept[k] = extra[k]
		size += cost
	}
	if len(kept) == 0 {
		return nil
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return nil
	}
	s := string(b)
	return &s
}

// truncateUTF8 cuts s to at most max bytes without splitting a rune.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// netEventsCopyColumns is the column order of the COPY into net_events: every
// NetEvent column but `id` (the bigserial fills it), in model field order.
// netEventCopyRow MUST produce values in the same order — pgx binds
// positionally — and TestNetEventsCopyColumns_MatchModel pins both against
// the model's schema, so a column added to the model without a slot here
// fails the build's tests rather than the first production COPY.
var netEventsCopyColumns = []string{
	"ts", "device_id", "probe_id",
	"activity", "action", "vendor_event_id",
	"src_ip", "src_port", "dst_ip", "dst_port", "proto", "src_mac", "dst_mac",
	"src_if", "dst_if", "src_zone", "dst_zone", "src_role", "dst_role", "direction",
	"rule_key", "rule_uid", "rule_id", "rule_name", "rule_index", "ruleset",
	"user_name", "user_group", "app", "app_cat", "app_risk", "dev_type", "os_name", "src_hostname",
	"bytes_out", "bytes_in", "pkts_out", "pkts_in", "duration_ms", "session_id",
	"nat_src_ip", "nat_src_port", "nat_dst_ip", "nat_dst_port",
	"src_country", "dst_country", "threat_flag",
	"url_host", "url_path", "dns_qname", "dns_qtype", "web_cat",
	"raw_id", "raw_ts", "extra",
}

// netEventCopyRow renders one row for the COPY, in netEventsCopyColumns
// order. inet / macaddr columns are handed to pgx as netip.Addr /
// net.HardwareAddr so they take the binary encoders directly; every other
// pointer goes through as is (pgx writes NULL for a nil pointer).
func netEventCopyRow(e *models.NetEvent) []any {
	return []any{
		e.Ts, int64(e.DeviceID), int64(e.ProbeID),
		e.Activity, e.Action, e.VendorEventID,
		inetValue(e.SrcIP), e.SrcPort, inetValue(e.DstIP), e.DstPort, e.Proto, macValue(e.SrcMAC), macValue(e.DstMAC),
		e.SrcIf, e.DstIf, e.SrcZone, e.DstZone, e.SrcRole, e.DstRole, e.Direction,
		e.RuleKey, e.RuleUID, e.RuleID, e.RuleName, e.RuleIndex, e.Ruleset,
		e.UserName, e.UserGroup, e.App, e.AppCat, e.AppRisk, e.DevType, e.OSName, e.SrcHostname,
		e.BytesOut, e.BytesIn, e.PktsOut, e.PktsIn, e.DurationMS, e.SessionID,
		inetValue(e.NatSrcIP), e.NatSrcPort, inetValue(e.NatDstIP), e.NatDstPort,
		e.SrcCountry, e.DstCountry, e.ThreatFlag,
		e.URLHost, e.URLPath, e.DNSQName, e.DNSQType, e.WebCat,
		e.RawID, e.RawTS, e.Extra,
	}
}

// inetValue is the COPY value for an inet column: nil, a netip.Addr, or —
// for text that is not an address, which the mapping never produces — the
// text itself for pgx to reject with a clear error.
func inetValue(s *string) any {
	if s == nil {
		return nil
	}
	if a, err := netip.ParseAddr(*s); err == nil {
		return a
	}
	return *s
}

func macValue(s *string) any {
	if s == nil {
		return nil
	}
	if m, err := net.ParseMAC(*s); err == nil {
		return m
	}
	return *s
}

// normalizedInsertBatch bounds the GORM multi-row INSERTs below: Postgres
// allows 65535 bind parameters per statement, and net_events has 55 columns.
const normalizedInsertBatch = 500

// SaveNetEvents persists a batch of net_events rows. On PostgreSQL it uses the
// dedicated pgx pool and the COPY protocol (the flow_samples writer's path,
// ~120k rows/s at batch 1000); on the SQLite test backend, and on a Postgres
// connection whose pool failed to open, it falls back to GORM's batched
// INSERT. A row whose ts has no leaf lands in net_events_default (never a
// failed batch). The GORM session's context propagates to pgx (AUDIT-032).
func (d *Database) SaveNetEvents(events []models.NetEvent) error {
	if len(events) == 0 {
		return nil
	}
	if d.pgxPool == nil {
		return insertInChunks(d.db, "net_events", events)
	}
	ctx := d.db.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return saveNetEventsPGX(ctx, d.pgxPool, events)
}

func saveNetEventsPGX(ctx context.Context, pool *pgxpool.Pool, events []models.NetEvent) error {
	rows := make([][]any, len(events))
	for i := range events {
		rows[i] = netEventCopyRow(&events[i])
	}
	n, err := pool.CopyFrom(ctx, pgx.Identifier{"net_events"}, netEventsCopyColumns, pgx.CopyFromRows(rows))
	if err != nil {
		return fmt.Errorf("pgx CopyFrom net_events (%d rows): %w", len(events), err)
	}
	if int(n) != len(events) {
		return fmt.Errorf("pgx CopyFrom net_events short write: inserted %d of %d", n, len(events))
	}
	return nil
}

// SaveSecEvents persists a batch of sec_events rows through the
// batchInsertWithFallback idiom (M26): one multi-row INSERT per chunk, and a
// per-row retry that drops only the unsalvageable rows when a chunk fails.
// sec_events is under 1% of the event volume, so no COPY path.
func (d *Database) SaveSecEvents(events []models.SecEvent) error {
	if len(events) == 0 {
		return nil
	}
	return insertInChunks(d.db, "sec_events", events)
}

// insertInChunks is batchInsertWithFallback over normalizedInsertBatch-sized
// chunks, so a wide table never exceeds the bind-parameter limit.
func insertInChunks[T any](db *gorm.DB, kind string, rows []T) error {
	for start := 0; start < len(rows); start += normalizedInsertBatch {
		end := start + normalizedInsertBatch
		if end > len(rows) {
			end = len(rows)
		}
		if err := batchInsertWithFallback(db, kind, rows[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// UpsertFwRules merges rule catalog rows into fw_rules on (device_id,
// rule_key): first_seen keeps the earliest, last_seen the latest (so a
// backfill replaying older rows cannot move either the wrong way), the
// identity parts and the API-fed fields fill in when the new row supplies
// them and are kept otherwise, and source never downgrades (api > config
// backup > log). Duplicates within the batch are merged first — Postgres
// rejects an INSERT ... ON CONFLICT that touches the same row twice.
func (d *Database) UpsertFwRules(rules []models.FwRule) error {
	if len(rules) == 0 {
		return nil
	}
	type key struct {
		dev uint
		rk  string
	}
	merged := make([]models.FwRule, 0, len(rules))
	at := map[key]int{}
	for _, r := range rules {
		k := key{r.DeviceID, r.RuleKey}
		i, ok := at[k]
		if !ok {
			at[k] = len(merged)
			merged = append(merged, r)
			continue
		}
		m := &merged[i]
		if r.FirstSeen.Before(m.FirstSeen) {
			m.FirstSeen = r.FirstSeen
		}
		if r.LastSeen.After(m.LastSeen) {
			m.LastSeen = r.LastSeen
		}
		if r.Source > m.Source {
			m.Source = r.Source
		}
		// Same rule as the ON CONFLICT below: the newest non-nil value wins.
		fillStr(&m.RuleUID, r.RuleUID)
		fillStr(&m.RuleName, r.RuleName)
		fillStr(&m.Ruleset, r.Ruleset)
		fillStr(&m.Extra, r.Extra)
		if r.RuleID != nil {
			m.RuleID = r.RuleID
		}
		if r.RuleIndex != nil {
			m.RuleIndex = r.RuleIndex
		}
		if r.Enabled != nil {
			m.Enabled = r.Enabled
		}
		if r.Position != nil {
			m.Position = r.Position
		}
	}
	keep := func(col string) clause.Expr {
		return gorm.Expr(fmt.Sprintf("COALESCE(excluded.%s, fw_rules.%s)", col, col))
	}
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "device_id"}, {Name: "rule_key"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"first_seen": gorm.Expr(d.dialect.Least("fw_rules.first_seen", "excluded.first_seen")),
			"last_seen":  gorm.Expr(d.dialect.Greatest("fw_rules.last_seen", "excluded.last_seen")),
			"source":     gorm.Expr(d.dialect.Greatest("fw_rules.source", "excluded.source")),
			"rule_uid":   keep("rule_uid"),
			"rule_id":    keep("rule_id"),
			"rule_name":  keep("rule_name"),
			"rule_index": keep("rule_index"),
			"ruleset":    keep("ruleset"),
			"enabled":    keep("enabled"),
			"position":   keep("position"),
			"extra":      keep("extra"),
		}),
	}).CreateInBatches(&merged, normalizedInsertBatch).Error
}

// fillStr overwrites dst when src is supplied — COALESCE(excluded, existing)
// applied batch-wise, so the later non-nil value wins exactly as it would
// have had the rows arrived in separate batches.
func fillStr(dst **string, src *string) {
	if src != nil {
		*dst = src
	}
}

// FlushFieldObserved adds the in-memory (device, class, field) counters to
// device_field_observed: count accumulates, last_seen keeps the latest.
// Duplicate keys within the batch are summed first (same ON CONFLICT rule as
// UpsertFwRules).
func (d *Database) FlushFieldObserved(rows []models.DeviceFieldObserved) error {
	if len(rows) == 0 {
		return nil
	}
	type key struct {
		dev   uint
		class int16
		field string
	}
	merged := make([]models.DeviceFieldObserved, 0, len(rows))
	at := map[key]int{}
	for _, r := range rows {
		k := key{r.DeviceID, r.Class, r.Field}
		i, ok := at[k]
		if !ok {
			at[k] = len(merged)
			merged = append(merged, r)
			continue
		}
		merged[i].Count += r.Count
		if r.LastSeen.After(merged[i].LastSeen) {
			merged[i].LastSeen = r.LastSeen
		}
	}
	return d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "device_id"}, {Name: "class"}, {Name: "field"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"count":     gorm.Expr("device_field_observed.count + excluded.count"),
			"last_seen": gorm.Expr(d.dialect.Greatest("device_field_observed.last_seen", "excluded.last_seen")),
		}),
	}).CreateInBatches(&merged, normalizedInsertBatch).Error
}

// GetFieldObserved returns the device_field_observed rows seen since `since`,
// summed across classes (Class is 0 in the result) — the observed half the
// capability API joins with the static profile. deviceID 0 means every
// device. The table holds devices × classes × fields rows, so the rows are
// read and folded here rather than with SUM / MAX in SQL: SQLite's MAX over a
// datetime column comes back as text, and the fold is a few hundred rows.
func (d *Database) GetFieldObserved(deviceID uint, since time.Time) ([]models.DeviceFieldObserved, error) {
	q := d.db.Where("last_seen >= ?", since)
	if deviceID != 0 {
		q = q.Where("device_id = ?", deviceID)
	}
	var rows []models.DeviceFieldObserved
	if err := q.Order("device_id, field, class").Find(&rows).Error; err != nil {
		return nil, err
	}
	type key struct {
		dev   uint
		field string
	}
	out := make([]models.DeviceFieldObserved, 0, len(rows))
	at := map[key]int{}
	for _, r := range rows {
		k := key{r.DeviceID, r.Field}
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			r.ID, r.Class = 0, 0
			out = append(out, r)
			continue
		}
		out[i].Count += r.Count
		if r.LastSeen.After(out[i].LastSeen) {
			out[i].LastSeen = r.LastSeen
		}
	}
	return out, nil
}

// InsertSettingIfAbsent writes a system setting only when its key does not
// exist yet (INSERT ... ON CONFLICT (key) DO NOTHING) and reports whether this
// call inserted it. It is for write-once watermarks such as
// normalize_ingest_started_at: a read-then-upsert would move the watermark
// whenever the read failed transiently, and the S-5 backfill bounds itself by
// it, so the row must never be overwritten by the ingest.
func (d *Database) InsertSettingIfAbsent(setting *models.SystemSetting) (bool, error) {
	res := d.db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoNothing: true}).Create(setting)
	if res.Error != nil {
		return false, fmt.Errorf("insert setting %q if absent: %w", setting.Key, res.Error)
	}
	return res.RowsAffected > 0, nil
}
