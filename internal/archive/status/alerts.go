package status

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"firewall-mon/internal/archive/export"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
)

// The raw archive's alerts. The poller evaluates them on its 5-minute
// server-health tick (cmd/poller/archivealerts.go) from Build's Status, and
// fires or resolves them through the alert engine's device-less path
// (alerts.CheckServerConditions: policy, event rules, cooldown, maintenance,
// recovery notifications). Each is keyed per stream or per table.
//
// Thresholds are system settings (the Alerting page's global defaults; 0
// turns one off): the operator's defaults are a syslog lag of 26 h and a flow
// lag of 3 h.

// Setting keys and defaults of the archive alert thresholds.
const (
	LagHoursSyslogKey   = "archive_lag_alert_hours_syslog"
	LagHoursFlowsKey    = "archive_lag_alert_hours_flows"
	LagHoursCountersKey = "archive_lag_alert_hours_counters"
	SealOverdueDaysKey  = "archive_seal_overdue_alert_days"
	HeldHoursKey        = "retention_held_alert_hours"
	UnsettledHoursKey   = "archive_unsettled_alert_hours"

	LagHoursSyslogDefault   = 26
	LagHoursFlowsDefault    = 3
	LagHoursCountersDefault = 26
	SealOverdueDaysDefault  = 3
	HeldHoursDefault        = 6
	UnsettledHoursDefault   = 6

	// ThresholdMax bounds every threshold (hours or days).
	ThresholdMax = 720
)

// ThresholdDefaults maps each threshold setting to its default.
var ThresholdDefaults = map[string]int{
	LagHoursSyslogKey: LagHoursSyslogDefault, LagHoursFlowsKey: LagHoursFlowsDefault,
	LagHoursCountersKey: LagHoursCountersDefault, SealOverdueDaysKey: SealOverdueDaysDefault,
	HeldHoursKey: HeldHoursDefault, UnsettledHoursKey: UnsettledHoursDefault,
}

// Thresholds are the alert thresholds in force (0 = that alert is off).
type Thresholds struct {
	LagSyslog, LagFlows, LagCounters time.Duration
	SealOverdueDays                  float64
	Held                             time.Duration
	Unsettled                        time.Duration
}

// ThresholdKeys lists the threshold settings.
func ThresholdKeys() []string {
	keys := make([]string, 0, len(ThresholdDefaults))
	for k := range ThresholdDefaults {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ReadThresholds builds the thresholds from the stored settings (key →
// value); a key that is absent, blank, not a whole number or outside
// 0..ThresholdMax takes its default.
func ReadThresholds(stored map[string]string) Thresholds {
	v := func(key string) int {
		def := ThresholdDefaults[key]
		n, err := strconv.Atoi(strings.TrimSpace(stored[key]))
		if err != nil || n < 0 || n > ThresholdMax {
			return def
		}
		return n
	}
	return Thresholds{
		LagSyslog:       time.Duration(v(LagHoursSyslogKey)) * time.Hour,
		LagFlows:        time.Duration(v(LagHoursFlowsKey)) * time.Hour,
		LagCounters:     time.Duration(v(LagHoursCountersKey)) * time.Hour,
		SealOverdueDays: float64(v(SealOverdueDaysKey)),
		Held:            time.Duration(v(HeldHoursKey)) * time.Hour,
		Unsettled:       time.Duration(v(UnsettledHoursKey)) * time.Hour,
	}
}

// DailySustain is how long a daily table's lag (syslog, sflow-counters) must
// stay above its threshold before ARCHIVE_LAG fires. Their chunk for a day is
// cut ARCHIVE_MIN_AGE_HOURS (2) after midnight UTC and then settles, exports
// (a day of syslog is ~11 min at 5 000 rows/s) and is read back, so the lag
// peaks every day a little past 24 h + 2 h — just over the 26 h default — and
// falls back to ~2 h when the chunk is verified. The hourly flow streams peak
// at about 1 h, far below their 3 h.
const DailySustain = time.Hour

// GateUnreadableAfter is how long the retention gate's reads of the stream
// switches may keep failing before ARCHIVE_GATE_UNREADABLE fires: a brief
// database hiccup is retried every few seconds and resolves itself.
const GateUnreadableAfter = 15 * time.Minute

// GateReadCondition is ARCHIVE_GATE_UNREADABLE from the gate's own record of
// its reads (database.ArchiveGateReadHealth, in the poller that runs the
// deletes): breached while they have failed for longer than
// GateUnreadableAfter. Unlike the other archive alerts it does not need the
// status: a database that fails the gate's read may fail Build too.
func GateReadCondition(h database.ArchiveGateHealth, now time.Time) Condition {
	c := Condition{Type: models.AlertTypeArchiveGateUnreadable, Label: "switches", Known: true, Fields: map[string]string{},
		Recovery: "The retention gate reads the archive's stream switches again"}
	if h.FailingSince == nil {
		return c
	}
	failing := now.Sub(*h.FailingSince)
	c.Breached = failing > GateUnreadableAfter
	what := "it keeps the stream switches it read last, so a change saved on the admin page is not applied"
	c.Fields["holding"] = "last"
	if h.HoldingAll {
		what = "it holds the retention, aggregation and rollup deletes of every archived table until a read succeeds"
		c.Fields["holding"] = "all"
	}
	c.Message = fmt.Sprintf("The archive's retention gate has not been able to read the stream switches for %s (since %s): %s; %s",
		hours(failing), h.FailingSince.UTC().Format(time.RFC3339), what, h.Error)
	return c
}

// unsettledWaits are the wait reasons ARCHIVE_UNSETTLED_LONG watches;
// "settling" is the normal short window after every cut.
var unsettledWaits = map[string]bool{"open_writer": true, "unattached_leaf": true, "no_statement_timeout": true}

// Condition is one alert instance's state, mapped by the poller onto
// alerts.ServerCondition.
type Condition struct {
	Type models.AlertType
	// Label is the instance (a stream or a table): Key and Metric derive
	// from it, stable per instance.
	Label string
	// Known false: the state could not be judged this time (the worker's
	// snapshot is missing or stale) — neither fire nor resolve.
	Known    bool
	Breached bool
	Message  string
	Recovery string
	Fields   map[string]string
}

// Key is the alert engine's cooldown / active key of c.
func (c Condition) Key() string { return strings.ToLower(string(c.Type)) + "_" + c.Label }

// Metric is the alert row's MetricName of c.
func (c Condition) Metric() string { return strings.ToLower(string(c.Type)) + "_" + c.Label }

// DiskTrend is whether the database volume is growing (its free space
// dropped since the comparison sample). Known false — an external database,
// or no sample to compare with — counts as growing for RETENTION_HELD: held
// rows cost disk wherever the database lives, and "could not measure" must
// not read as healthy.
type DiskTrend struct {
	Known   bool
	Growing bool
	Detail  string
}

// Evaluator turns a Status into Conditions. It remembers since when each
// daily table's lag has been above its threshold (DailySustain); a restart
// forgets that, which delays such an alert by at most DailySustain. It also
// remembers which RETENTION_HELD alerts are active (the disk trend only fires
// them).
//
// It also remembers since when an enabled table has had no chunk at all: a
// bucket that never passes the preflight (wrong credentials at enabling) cuts
// none, so there is no lag to measure — yet the gate holds every raw row of
// the table (V = 0). ARCHIVE_LAG counts that time as the lag.
type Evaluator struct {
	mu       sync.Mutex
	lagAbove map[string]time.Time
	noChunks map[string]time.Time
	// heldActive: tables whose RETENTION_HELD is breached (it fired, or
	// would have but for a rule or cooldown).
	heldActive map[string]bool
}

// NewEvaluator returns an Evaluator with no history.
func NewEvaluator() *Evaluator {
	return &Evaluator{lagAbove: map[string]time.Time{}, noChunks: map[string]time.Time{}, heldActive: map[string]bool{}}
}

func hours(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
	return fmt.Sprintf("%.1f h", d.Hours())
}

func secs(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// lagOf is table's lag threshold and whether its chunks are daily.
func (th Thresholds) lagOf(table string) (time.Duration, bool) {
	switch table {
	case export.TableSyslog:
		return th.LagSyslog, true
	case export.TableCounters:
		return th.LagCounters, true
	}
	return th.LagFlows, false
}

// preflightNote says what the worker's snapshot tells about a stream that
// cut no chunk.
func preflightNote(st *Status) string {
	w := st.Worker
	switch {
	case w == nil:
		return "The archive worker has recorded no state (is the poller running with the archive enabled?)."
	case w.Stale:
		return "The archive worker's state is stale (last written " + w.SeenAt.Format(time.RFC3339) + ")."
	case !w.PreflightOK:
		for _, e := range w.Stages {
			if e.Stage == "preflight" {
				return "The bucket preflight fails: " + e.Error
			}
		}
		return "The bucket preflight has not passed."
	}
	return "See the Raw Archive card on the Retention page."
}

// Conditions evaluates every archive alert at st.GeneratedAt. A stream or
// table that is not enabled is never breached (so its open alerts resolve
// after archiving is turned off).
func (e *Evaluator) Conditions(st *Status, th Thresholds, disk DiskTrend) []Condition {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := st.GeneratedAt
	var out []Condition

	// ARCHIVE_LAG per table: sflow and netflow are cut from one flow_samples
	// chunk and always share its lag, so one alert names both.
	for _, t := range st.Tables {
		names := strings.Join(t.Streams, " and ")
		c := Condition{Type: models.AlertTypeArchiveLag, Label: t.Table, Known: true,
			Fields: map[string]string{"table": t.Table, "stream": strings.Join(t.Streams, ","), "gate_stream": t.GateStream}}
		limit, daily := th.lagOf(t.Table)
		if !t.Enabled || t.LagSeconds != nil {
			delete(e.noChunks, t.Table)
		}
		if t.Enabled && t.LagSeconds == nil {
			// No chunk yet: the lag runs from when this process first saw it.
			first, ok := e.noChunks[t.Table]
			if !ok {
				e.noChunks[t.Table], first = now, now
			}
			waited := now.Sub(first)
			c.Breached = limit > 0 && waited > limit
			c.Message = fmt.Sprintf("Raw archive of %s (%s) is enabled but has cut no chunk for %s (threshold %s): nothing of it is archived and its raw deletes wait. %s",
				names, t.Table, hours(waited), hours(limit), preflightNote(st))
			c.Recovery = fmt.Sprintf("Raw archive of %s has cut its first chunk", names)
			out = append(out, c)
			continue
		}
		var lag time.Duration
		if t.LagSeconds != nil {
			lag = secs(*t.LagSeconds)
		}
		over := t.Enabled && limit > 0 && t.LagSeconds != nil && lag > limit
		if !over {
			delete(e.lagAbove, t.Table)
		} else if daily {
			first, ok := e.lagAbove[t.Table]
			if !ok {
				e.lagAbove[t.Table], first = now, now
			}
			over = now.Sub(first) >= DailySustain
		}
		c.Breached = over
		c.Message = fmt.Sprintf("Raw archive of %s (%s) is %s behind (threshold %s): its verified data ends %s",
			names, t.Table, hours(lag), hours(limit), now.Add(-lag).Format(time.RFC3339))
		c.Recovery = fmt.Sprintf("Raw archive of %s caught up: %s behind", names, hours(lag))
		out = append(out, c)
	}

	gated := map[string]bool{}
	for _, g := range st.Gates {
		gated[g.Stream] = g.Gated
	}
	parked := map[string][]ParkedChunk{}
	for _, p := range st.NeedsAttention {
		parked[p.Table] = append(parked[p.Table], p)
	}
	for _, t := range st.Tables {
		// ARCHIVE_NEEDS_ATTENTION per table.
		ps := parked[t.Table]
		c := Condition{Type: models.AlertTypeArchiveNeedsAttention, Label: t.Table, Known: true,
			Breached: len(ps) > 0, Fields: map[string]string{"table": t.Table, "gate_stream": t.GateStream}}
		if len(ps) > 0 {
			ids := make([]string, 0, len(ps))
			holding := 0
			for i, p := range ps {
				if p.HoldsGate {
					holding++
				}
				if i < 5 {
					ids = append(ids, fmt.Sprintf("%d (seq %d)", p.ID, p.Seq))
				}
			}
			if len(ps) > 5 {
				ids = append(ids, fmt.Sprintf("and %d more", len(ps)-5))
			}
			c.Message = fmt.Sprintf("%d archive chunk(s) of %s are parked in needs_attention: %s; %d hold its raw deletes. See the Retention page or fwmon-api archive --status.",
				len(ps), t.Table, strings.Join(ids, ", "), holding)
		}
		c.Recovery = fmt.Sprintf("No archive chunk of %s needs attention any more", t.Table)
		out = append(out, c)

		// RETENTION_HELD per table.
		var held time.Duration
		if t.Retention != nil {
			held = secs(t.Retention.HeldSeconds)
		}
		c = Condition{Type: models.AlertTypeRetentionHeld, Label: t.Table, Known: true,
			Fields: map[string]string{"table": t.Table, "gate_stream": t.GateStream}}
		// The disk trend only decides the FIRE: once active the alert stays
		// while the hold lasts — one free-space rise (a partition drop, WAL
		// recycling) must not resolve it, and the cooldown would then mute
		// its re-fire while rows are still held.
		growing := !disk.Known || disk.Growing
		holding := t.Enabled && gated[t.GateStream] && th.Held > 0 && held > th.Held
		c.Breached = holding && (growing || e.heldActive[t.Table])
		if c.Breached {
			e.heldActive[t.Table] = true
		} else {
			delete(e.heldActive, t.Table)
		}
		if t.Retention != nil {
			c.Message = fmt.Sprintf("The archive's retention gate holds unarchived rows of %s up to %s past their window (%s; threshold %s) and the database volume is growing (%s). Fix the archive, or release the gate for a few hours: fwmon-api archive --override %s --for 6h --reason \"...\"",
				t.Table, hours(held), t.Retention.Window, hours(th.Held), disk.Detail, t.GateStream)
		}
		c.Recovery = fmt.Sprintf("The retention gate no longer holds rows of %s far past their window", t.Table)
		out = append(out, c)

		// ARCHIVE_UNSETTLED_LONG per table: needs a fresh worker snapshot.
		c = Condition{Type: models.AlertTypeArchiveUnsettledLong, Label: t.Table,
			Fields: map[string]string{"table": t.Table, "gate_stream": t.GateStream}}
		fresh := st.Worker != nil && !st.Worker.Stale
		switch {
		case !t.Enabled || th.Unsettled == 0:
			c.Known = true
		case !fresh:
			c.Known = false // the worker is not running here, or not writing: hold the state
		default:
			c.Known = true
			if u := t.Unsettled; u != nil && unsettledWaits[u.Reason] {
				waited := secs(u.ForSeconds)
				c.Breached = waited > th.Unsettled
				c.Fields["reason"] = u.Reason
				c.Message = fmt.Sprintf("The archive of %s has waited %s (threshold %s) to export its next chunk: %s — %s",
					t.Table, hours(waited), hours(th.Unsettled), u.Reason, u.Detail)
			}
		}
		c.Recovery = fmt.Sprintf("The archive of %s is no longer waiting on its next chunk", t.Table)
		out = append(out, c)
	}

	// ARCHIVE_SEAL_OVERDUE per stream.
	for _, s := range st.Streams {
		c := Condition{Type: models.AlertTypeArchiveSealOverdue, Label: s.Stream, Known: true,
			Fields: map[string]string{"stream": s.Stream, "table": s.Table}}
		c.Breached = s.Enabled && th.SealOverdueDays > 0 && s.UnsealedDays > th.SealOverdueDays
		why := ""
		for _, m := range s.Months {
			if m.Month == s.OldestUnsealed && m.Error != "" {
				why = ": " + m.Error
			}
		}
		c.Message = fmt.Sprintf("Month %s of the raw archive stream %s is %.1f days past its seal time and not sealed (threshold %.0f days)%s",
			s.OldestUnsealed, s.Stream, s.UnsealedDays, th.SealOverdueDays, why)
		c.Recovery = fmt.Sprintf("Every due month of the raw archive stream %s is sealed", s.Stream)
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
