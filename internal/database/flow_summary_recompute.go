package database

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"firewall-mon/internal/models"
)

// Recomputing the summaries after a reclassification.
//
// The flow-history reclassification (flow_reclass.go) re-stamps rollup rows IN
// PLACE. The summary pass only notices changes that arrive as new rollup ids
// (its dirty walk) or history it never built (its backfill), so without this
// step every summary bucket built before the reclassification would keep the
// old direction forever, and Top services on long ranges would stay partial.
//
// When a reclassification run completes it posts a request naming the oldest
// hour it re-stamped. The summary pass — the only writer of what follows,
// under its own advisory lock — merges that request into a per-tier cursor
// and, after both tiers' routine work each cycle, walks the tier's owned
// buckets from the cursor, recomputing each with summariseBucket. A bucket that
// fails is kept on a retry list rather than skipped: summariseBucket is
// delete-then-insert in one transaction, so a failed bucket keeps its OLD rows
// and nothing else would ever revisit it. Only when both tiers have walked to
// the end with nothing left to retry is flow_summary_service_since removed —
// the single thing the reader checks before trusting the service dimension.

const flowSummaryRecomputeStatusKey = "flow_summary_recompute_status"

var (
	// maxRecomputeRetries bounds a tier's retry list; at the bound the walk
	// stops advancing (and the status says so) rather than hide failures.
	maxRecomputeRetries = 50
	// flowSummaryRecomputeReserve: a daily recompute bucket costs 14-30 s, so
	// one starts only with this much of the cycle left.
	flowSummaryRecomputeReserve = 20 * time.Second
	// flowSummaryRecomputeForceAfter: after this many consecutive cycles in
	// which the daily tier found no time left, one daily bucket runs anyway —
	// routine work alone can fill the cycle, and the rebuild must still move.
	flowSummaryRecomputeForceAfter = 12
	// flowSummaryRecomputeHourlyRetries caps hourly retries per cycle so a
	// list of failing buckets cannot starve the walk. The daily tier's retries
	// count against its shared maxPerPass.
	flowSummaryRecomputeHourlyRetries = 10

	// flowSummaryRecomputeHook is a test-only injection point that runs before
	// each bucket the recompute step (only) rebuilds.
	flowSummaryRecomputeHook func(interval string, bucket time.Time) error

	// recomputeBlockedCycles counts consecutive cycles the daily tier had no
	// time left. Process-local on purpose: it only paces the forced bucket.
	recomputeBlockedCycles int
)

// flowSummaryConsumeHook is a test-only injection point at the start of
// consumeRecomputeRequest (the one step of a cycle that runs before any tier).
var flowSummaryConsumeHook func()

func recomputeCursorKey(interval string) string { return "flow_summary_recompute_" + interval }
func recomputeDoneKey(interval string) string   { return "flow_summary_recompute_" + interval + "_done" }
func recomputeRetryKey(interval string) string {
	return "flow_summary_recompute_" + interval + "_retry"
}

// recomputeMark is a revision and a bucket, stored as "rev|RFC3339".
type recomputeMark struct {
	rev    uint16
	bucket time.Time
}

func parseRecomputeMark(raw string) (recomputeMark, bool) {
	rev, ts, ok := strings.Cut(strings.TrimSpace(raw), "|")
	if !ok {
		return recomputeMark{}, false
	}
	r, err := strconv.Atoi(rev)
	if err != nil || r < 1 || r > 65535 {
		return recomputeMark{}, false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return recomputeMark{}, false
	}
	return recomputeMark{rev: uint16(r), bucket: t.UTC()}, true
}

func (m recomputeMark) String() string {
	return fmt.Sprintf("%d|%s", m.rev, m.bucket.UTC().Format(time.RFC3339))
}

// The recompute's state is a handful of settings: a request, and per tier a
// cursor, a retry list and a done mark. Every decision that WRITES or DELETES
// one of them reads what it needs through recomputeRead, which reports a failed
// read. (Two reads that only shape the STATUS text stay lenient: the boundary
// probe behind its "waiting" reason, and the readers the API uses.)
//
// WHY: GetSettingValue answers "" for a database error exactly as for a key
// that was never written, and here "absent" is never neutral. A cursor read
// as absent let consumeRecomputeRequest overwrite it with the request's later
// bucket, so the buckets in between were never recomputed. A retry list read
// as absent was then SAVED as empty, which deletes the key: buckets still
// holding pre-reclassification rows were forgotten, the tier finished "done"
// and the service boundary was removed for good. One transient error each.
//
// Strict means the READ. A value that was read and does not parse is treated
// as absent, as it always was — a garbled cursor that aborted every cycle
// would stall the rebuild (and the hybrid read with it) until someone edited
// the setting by hand.
type recomputeSettings map[string]string

func (d *Database) recomputeRead(keys ...string) (recomputeSettings, error) {
	vals, err := d.summarySettings(context.Background(), keys...)
	return recomputeSettings(vals), err
}

// has reports whether the key is present at all (a blank value is present).
func (v recomputeSettings) has(key string) bool {
	_, ok := v[key]
	return ok
}

func (v recomputeSettings) cursor(interval string) (recomputeMark, bool) {
	raw, ok := v[recomputeCursorKey(interval)]
	if !ok {
		return recomputeMark{}, false
	}
	m, ok := parseRecomputeMark(raw)
	if !ok {
		log.Printf("Flow summary: the %s recompute cursor %q is unreadable; the rebuild of that tier is stalled until a new request", interval, raw)
	}
	return m, ok
}

func (v recomputeSettings) retries(interval string) []time.Time {
	return parseRecomputeRetries(v[recomputeRetryKey(interval)])
}

// recomputeCursor and recomputeRetries are the LENIENT readers, for reporting
// only (the status the API shows). Nothing that writes may be decided on them.
func (d *Database) recomputeCursor(interval string) (recomputeMark, bool) {
	raw, ok := d.GetSettingValue(recomputeCursorKey(interval))
	if !ok {
		return recomputeMark{}, false
	}
	return recomputeSettings{recomputeCursorKey(interval): raw}.cursor(interval)
}

func (d *Database) recomputeRetries(interval string) []time.Time {
	raw, _ := d.GetSettingValue(recomputeRetryKey(interval))
	return parseRecomputeRetries(raw)
}

func parseRecomputeRetries(raw string) []time.Time {
	if raw == "" {
		return nil
	}
	var stamps []string
	if json.Unmarshal([]byte(raw), &stamps) != nil {
		return nil
	}
	out := make([]time.Time, 0, len(stamps))
	for _, s := range stamps {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			out = append(out, t.UTC())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

func (d *Database) saveRecomputeRetries(interval string, list []time.Time) {
	if len(list) == 0 {
		d.deleteSetting(recomputeRetryKey(interval))
		return
	}
	seen := map[string]bool{}
	stamps := make([]string, 0, len(list))
	for _, t := range list {
		s := t.UTC().Format(time.RFC3339)
		if !seen[s] {
			seen[s] = true
			stamps = append(stamps, s)
		}
	}
	b, _ := json.Marshal(stamps)
	_ = d.setReclassSetting(recomputeRetryKey(interval), string(b))
}

func (d *Database) deleteSetting(key string) {
	if err := d.db.Where(`"key" = ?`, key).Delete(&models.SystemSetting{}).Error; err != nil {
		log.Printf("Flow summary: could not delete %s: %v", key, err)
	}
}

// consumeRecomputeRequest merges a posted request into each tier's cursor by
// revision: a newer revision replaces the cursor (at the earlier of the two
// buckets) and clears the tier's done mark; the same revision takes the
// earlier bucket; an older one is ignored. The request is then deleted only if
// unchanged, so a newer request posted meanwhile survives to the next cycle.
func (d *Database) consumeRecomputeRequest() {
	if flowSummaryConsumeHook != nil {
		flowSummaryConsumeHook()
	}
	keys := []string{flowSummaryRecomputeRequestKey}
	for _, tier := range flowSummaryTiers {
		keys = append(keys, recomputeCursorKey(tier.interval))
	}
	vals, err := d.recomputeRead(keys...)
	if err != nil {
		log.Printf("Flow summary: recompute request not consumed this cycle: %v", err)
		return // the request is kept; retried next cycle
	}
	raw := vals[flowSummaryRecomputeRequestKey]
	if raw == "" {
		return
	}
	req, ok := parseRecomputeMark(raw)
	if ok {
		for _, tier := range flowSummaryTiers {
			cur, has := vals.cursor(tier.interval)
			next := recomputeMark{rev: req.rev, bucket: tier.bucketOf(req.bucket)}
			switch {
			case !has || req.rev > cur.rev:
				if has && cur.bucket.Before(next.bucket) {
					next.bucket = cur.bucket
				}
				d.deleteSetting(recomputeDoneKey(tier.interval))
			case req.rev == cur.rev:
				if cur.bucket.Before(next.bucket) {
					next.bucket = cur.bucket
				}
			default:
				continue // an older revision's request: superseded
			}
			if err := d.setReclassSetting(recomputeCursorKey(tier.interval), next.String()); err != nil {
				log.Printf("Flow summary: could not record the %s recompute cursor: %v", tier.interval, err)
				return // keep the request; retried next cycle
			}
		}
		log.Printf("Flow summary: recomputing from %s after reclassification revision %d", req.bucket.Format(time.RFC3339), req.rev)
	} else {
		log.Printf("Flow summary: ignoring an unreadable recompute request %q", raw)
	}
	if err := d.db.Where(`"key" = ? AND value = ?`, flowSummaryRecomputeRequestKey, raw).Delete(&models.SystemSetting{}).Error; err != nil {
		log.Printf("Flow summary: could not clear the recompute request: %v", err)
	}
}

// FlowSummaryRecomputeTier is one tier's rebuild progress.
type FlowSummaryRecomputeTier struct {
	State           string   `json:"state"` // waiting, rebuilding, done
	Remaining       int64    `json:"remaining_buckets"`
	Done            int64    `json:"done_buckets"`
	BucketsPerCycle float64  `json:"buckets_per_cycle"`
	Failing         []string `json:"failing,omitempty"`
}

// FlowSummaryRecomputeStatus is the summary rebuild's progress, for the status
// view. Active reports whether a rebuild is due or under way.
type FlowSummaryRecomputeStatus struct {
	Rev           uint16                               `json:"rev"`
	Tiers         map[string]*FlowSummaryRecomputeTier `json:"tiers"`
	WaitingReason string                               `json:"waiting_reason,omitempty"`
	UpdatedAt     time.Time                            `json:"updated_at"`
	Active        bool                                 `json:"-"`
}

// GetFlowSummaryRecomputeStatus returns the last written progress and whether
// a rebuild is pending: a request posted, or a cursor or retry list left.
func (d *Database) GetFlowSummaryRecomputeStatus() FlowSummaryRecomputeStatus {
	var st FlowSummaryRecomputeStatus
	if raw, ok := d.GetSettingValue(flowSummaryRecomputeStatusKey); ok {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	if _, ok := d.GetSettingValue(flowSummaryRecomputeRequestKey); ok {
		st.Active = true
	}
	for _, tier := range flowSummaryTiers {
		if _, ok := d.recomputeCursor(tier.interval); ok {
			st.Active = true
		}
		if len(d.recomputeRetries(tier.interval)) > 0 {
			st.Active = true
		}
	}
	return st
}

// runSummaryRecompute runs the recompute step for every tier, daily first,
// with whatever the cycle's deadline leaves, then removes the service
// boundary once everything is rebuilt. Returns the buckets recomputed.
func (d *Database) runSummaryRecompute(ordered []flowSummaryTier, bounds map[string]tierBounds, deadline time.Time, rep *summaryReporter) int {
	var st FlowSummaryRecomputeStatus
	// The status is history (how many buckets are done, at what rate). If it
	// cannot be READ this cycle it is not written either: writing would
	// replace that history with this cycle's zeroes.
	// The tiers' cursors come with it: the status's revision is taken from
	// them, and a cursor read as absent would reset the counters to zero for
	// a rebuild that is in fact advancing.
	statusKeys := []string{flowSummaryRecomputeStatusKey}
	for _, tier := range ordered {
		statusKeys = append(statusKeys, recomputeCursorKey(tier.interval))
	}
	statusVals, statusErr := d.recomputeRead(statusKeys...)
	if statusErr != nil {
		log.Printf("Flow summary: recompute status unreadable, not updated this cycle: %v", statusErr)
	} else if raw := statusVals[flowSummaryRecomputeStatusKey]; raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	if st.Tiers == nil {
		st.Tiers = map[string]*FlowSummaryRecomputeTier{}
	}
	// A stored null entry (a hand edit, a truncated write) would be
	// dereferenced by both loops below, on every cycle.
	for k, ts := range st.Tiers {
		if ts == nil {
			delete(st.Tiers, k)
		}
	}
	// A newer revision's rebuild starts its counts afresh.
	for _, tier := range ordered {
		if cur, ok := statusVals.cursor(tier.interval); ok && cur.rev != st.Rev {
			st.Rev = cur.rev
			st.Tiers = map[string]*FlowSummaryRecomputeTier{}
			break
		}
	}
	// Read strictly, like the rest of the step's state: "is a
	// reclassification due or running?" read as "no" on a failed read would
	// let a tier walk — and finish — while history is being rewritten under
	// it. Unreadable means busy for this cycle.
	busy := true
	if vals, err := d.recomputeRead(FlowReclassDoneRevKey, FlowReclassTargetRevKey, flowReclassStateKey); err != nil {
		log.Printf("Flow summary: reclassification state unreadable; the recompute waits this cycle: %v", err)
	} else {
		busy = reclassBusyFrom(vals)
	}
	st.WaitingReason = ""
	total := 0
	anyActive := false
	allClean := true
	for _, b := range bounds {
		allClean = allClean && b.valid && (b.clean || b.ownsNothing)
	}
	stateBefore := map[string]string{}
	for k, ts := range st.Tiers {
		stateBefore[k] = ts.State
	}
	for _, tier := range ordered {
		ts := st.Tiers[tier.interval]
		if ts == nil {
			ts = &FlowSummaryRecomputeTier{}
			st.Tiers[tier.interval] = ts
		}
		// Bounded by the cycle deadline plus one bucket, so one tick per tier
		// keeps the health record's liveness current through the rebuild.
		rep.progress()
		n, active := d.recomputeTier(tier, bounds[tier.interval], deadline, busy, ts, &st)
		total += n
		anyActive = anyActive || active
	}
	stateChanged := false
	for k, ts := range st.Tiers {
		if stateBefore[k] != ts.State {
			stateChanged = true
		}
	}
	if allClean {
		d.maybeClearServiceSince()
	} else if _, held := d.GetSettingValue(flowSummaryServiceSinceKey); held && !anyActive {
		// Everything is rebuilt, but a routine summary bucket failed this
		// cycle: the boundary is held until it succeeds. Say why.
		st.WaitingReason = "a summary bucket keeps failing; see the log"
		stateChanged = true
	}
	if statusErr == nil && (anyActive || total > 0 || stateChanged) {
		st.UpdatedAt = time.Now().UTC()
		b, _ := json.Marshal(st)
		_ = d.setReclassSetting(flowSummaryRecomputeStatusKey, string(b))
	}
	if total > 0 {
		log.Printf("Flow summary: recomputed %d bucket(s) after reclassification", total)
	}
	return total
}

// recomputeTier advances one tier. active reports whether the tier still has
// a rebuild pending after this cycle.
func (d *Database) recomputeTier(tier flowSummaryTier, b tierBounds, deadline time.Time, busy bool,
	ts *FlowSummaryRecomputeTier, st *FlowSummaryRecomputeStatus) (recomputed int, active bool) {
	wait := func(reason string) (int, bool) {
		ts.State = "waiting"
		if st.WaitingReason == "" {
			st.WaitingReason = reason
		}
		return 0, true
	}
	vals, err := d.recomputeRead(recomputeCursorKey(tier.interval), recomputeRetryKey(tier.interval))
	if err != nil {
		// Nothing is decided, and above all nothing is saved, on a read that
		// failed: see recomputeSettings.
		log.Printf("Flow summary: %s recompute state unreadable this cycle: %v", tier.interval, err)
		return wait("the rebuild's progress could not be read; retrying")
	}
	cur, hasCur := vals.cursor(tier.interval)
	retries := vals.retries(tier.interval)
	if !hasCur && len(retries) == 0 {
		if ts.State != "done" && ts.State != "" {
			ts.State = "done"
		}
		if tier.interval == "1d" {
			recomputeBlockedCycles = 0
		}
		return 0, false
	}
	if hasCur && ts.State == "done" {
		// A cursor on a tier recorded as done is a new walk (a same-revision
		// re-arm): its counts start afresh.
		*ts = FlowSummaryRecomputeTier{}
	}
	if !b.valid {
		return wait("the summary pass failed; see the log")
	}
	if b.ownsNothing {
		// Nothing to rebuild in this tier: done trivially.
		d.finishRecomputeTier(tier, cur, hasCur, ts)
		return 0, false
	}
	if busy {
		return wait("waiting for the reclassification to finish")
	}
	if !b.caughtUp {
		return wait("waiting for the summary backfill to catch up")
	}

	owns := func(t time.Time) bool { return !t.Before(b.ownedFrom) && t.Before(b.ownedTo) }
	// A bucket the tier no longer owns was rebuilt by the tier that owns it now
	// (ownership moves only through promotion's new rows, which that tier's
	// dirty walk picks up). Rebuilding it here would be destructive: an hour
	// retried through the hourly tier deletes its day's daily rows.
	kept := retries[:0]
	for _, t := range retries {
		if owns(t) {
			kept = append(kept, t)
		}
	}
	retries = kept

	// How many buckets this cycle may start. The daily tier shares its cap
	// with its own backfill and needs a reserve of time per bucket.
	budget := -1 // unlimited, bounded by the deadline
	if tier.maxPerPass > 0 {
		budget = max(0, tier.maxPerPass-b.backfilled)
	}
	forced := false
	if tier.interval == "1d" {
		if budget == 0 || time.Until(deadline) < flowSummaryRecomputeReserve {
			recomputeBlockedCycles++
			if recomputeBlockedCycles < flowSummaryRecomputeForceAfter {
				d.saveRecomputeRetries(tier.interval, retries)
				return wait("no time left in the summary cycle after routine work")
			}
			forced, budget = true, 1
		}
		recomputeBlockedCycles = 0
	}
	canStart := func() bool {
		if budget == 0 {
			return false
		}
		if forced {
			return true
		}
		if tier.interval == "1d" {
			// Every daily bucket needs the reserve, not just the first.
			return time.Until(deadline) >= flowSummaryRecomputeReserve
		}
		return time.Now().Before(deadline)
	}
	attempt := func(bucket time.Time) bool {
		if budget > 0 {
			budget--
		}
		forced = false // at most one bucket past the deadline
		err := error(nil)
		if flowSummaryRecomputeHook != nil {
			err = flowSummaryRecomputeHook(tier.interval, bucket)
		}
		if err == nil {
			_, err = d.summariseBucket(tier, bucket)
		}
		if err != nil {
			log.Printf("Flow summary: recomputing %s bucket %s failed; it will be retried: %v",
				tier.interval, bucket.Format(time.RFC3339), err)
			return false
		}
		recomputed++
		ts.Done++
		return true
	}

	// Retries first, oldest first, capped so they cannot starve the walk.
	retryCap := len(retries)
	if tier.interval != "1d" {
		retryCap = min(retryCap, flowSummaryRecomputeHourlyRetries)
	}
	still := make([]time.Time, 0, len(retries))
	for i, t := range retries {
		if i < retryCap && canStart() && attempt(t) {
			continue
		}
		still = append(still, t)
	}
	retries = still

	// Then the walk from the cursor, over owned buckets only.
	if hasCur {
		bk := cur.bucket
		if bk.Before(b.ownedFrom) {
			bk = b.ownedFrom
		}
		for ; bk.Before(b.ownedTo) && canStart(); bk = bk.Add(tier.width) {
			if len(retries) >= maxRecomputeRetries {
				st.WaitingReason = fmt.Sprintf("%d summary buckets keep failing — see the log", len(retries))
				break
			}
			if !attempt(bk) && !containsTime(retries, bk) {
				retries = append(retries, bk)
			}
			cur.bucket = bk.Add(tier.width)
		}
		if cur.bucket.Before(b.ownedFrom) {
			cur.bucket = b.ownedFrom
		}
	}

	ts.Failing = ts.Failing[:0]
	for _, t := range retries {
		ts.Failing = append(ts.Failing, t.Format(time.RFC3339))
	}
	d.saveRecomputeRetries(tier.interval, retries)
	remaining := int64(0)
	if hasCur && cur.bucket.Before(b.ownedTo) {
		remaining = int64(b.ownedTo.Sub(cur.bucket) / tier.width)
	}
	ts.Remaining = remaining + int64(len(retries))
	// The rate is an average of what the recompute step actually did per
	// cycle; cycles spent waiting leave it unchanged.
	ts.BucketsPerCycle = 0.7*ts.BucketsPerCycle + 0.3*float64(recomputed)

	if hasCur && !cur.bucket.Before(b.ownedTo) && len(retries) == 0 {
		// Persist the cursor first: if recording the finish fails, the next
		// cycle resumes here rather than re-walking this cycle's work.
		_ = d.setReclassSetting(recomputeCursorKey(tier.interval), cur.String())
		d.finishRecomputeTier(tier, cur, true, ts)
		return recomputed, false
	}
	ts.State = "rebuilding"
	if hasCur {
		if err := d.setReclassSetting(recomputeCursorKey(tier.interval), cur.String()); err != nil {
			log.Printf("Flow summary: could not record the %s recompute cursor: %v", tier.interval, err)
		}
	}
	return recomputed, true
}

func (d *Database) finishRecomputeTier(tier flowSummaryTier, cur recomputeMark, hasCur bool, ts *FlowSummaryRecomputeTier) {
	rev := cur.rev
	if !hasCur {
		// Read strictly: a failed read would record the tier as done for
		// revision 0, which holds the service boundary until the next
		// reclassification.
		vals, err := d.recomputeRead(FlowReclassDoneRevKey)
		if err != nil {
			log.Printf("Flow summary: %s rebuild not recorded as done this cycle: %v", tier.interval, err)
			return
		}
		rev = parseDoneRev(vals[FlowReclassDoneRevKey])
	}
	if err := d.setReclassSetting(recomputeDoneKey(tier.interval), strconv.Itoa(int(rev))); err != nil {
		log.Printf("Flow summary: could not record the %s rebuild as done: %v", tier.interval, err)
		return
	}
	d.deleteSetting(recomputeCursorKey(tier.interval))
	d.deleteSetting(recomputeRetryKey(tier.interval))
	ts.State, ts.Remaining, ts.Failing = "done", 0, nil
	if tier.interval == "1d" {
		recomputeBlockedCycles = 0
	}
	log.Printf("Flow summary: %s summaries rebuilt for reclassification revision %d", tier.interval, rev)
}

// maybeClearServiceSince removes flow_summary_service_since once every summary
// bucket has been rebuilt for the current classification: both tiers done for
// the same revision, which is the completed and current one, with no request
// pending, no reclassification running and nothing left to retry.
// reclassBusyFrom: stored history is mid-rewrite (a reclassification due or
// under way), so buckets rebuilt now could mix old and new classifications. A
// run that finishes posts a fresh request, so nothing waiting here is lost.
// Decided from values the caller has already read STRICTLY — the completed
// revision, the target revision and the running state — never from a read
// that can turn an error into "not busy".
func reclassBusyFrom(vals recomputeSettings) bool {
	if parseDoneRev(vals[FlowReclassDoneRevKey]) < parseTargetRev(vals[FlowReclassTargetRevKey]) {
		return true
	}
	var running reclassState
	raw := vals[flowReclassStateKey]
	return raw != "" && json.Unmarshal([]byte(raw), &running) == nil && running.Rev != 0
}

func (d *Database) maybeClearServiceSince() {
	// Removing the boundary cannot be undone (only a migration ever wrote
	// it), so every fact it rests on is read strictly and in one go: a failed
	// read of "is a request pending?" or "is a reclassification due?" must
	// not be taken for "no".
	keys := []string{flowSummaryServiceSinceKey, flowSummaryRecomputeRequestKey,
		FlowReclassDoneRevKey, FlowReclassTargetRevKey, flowReclassStateKey}
	for _, tier := range flowSummaryTiers {
		keys = append(keys, recomputeDoneKey(tier.interval), recomputeCursorKey(tier.interval), recomputeRetryKey(tier.interval))
	}
	vals, err := d.recomputeRead(keys...)
	if err != nil {
		log.Printf("Flow summary: service boundary left in place this cycle: %v", err)
		return
	}
	if !vals.has(flowSummaryServiceSinceKey) || vals.has(flowSummaryRecomputeRequestKey) {
		return
	}
	done := parseDoneRev(vals[FlowReclassDoneRevKey])
	if reclassBusyFrom(vals) {
		return
	}
	for _, tier := range flowSummaryTiers {
		if raw, ok := vals[recomputeDoneKey(tier.interval)]; !ok || raw != strconv.Itoa(int(done)) {
			return
		}
		if _, has := vals.cursor(tier.interval); has {
			return
		}
		if len(vals.retries(tier.interval)) > 0 {
			return
		}
	}
	d.deleteSetting(flowSummaryServiceSinceKey)
	log.Printf("Flow summary: every bucket is rebuilt for revision %d; Top services now covers all of history", done)
}

func containsTime(list []time.Time, t time.Time) bool {
	for _, x := range list {
		if x.Equal(t) {
			return true
		}
	}
	return false
}
