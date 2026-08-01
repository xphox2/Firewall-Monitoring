package configdiff

import (
	"regexp"
	"strconv"
	"strings"
)

// ChangeAttribution is the who/how of a config change extracted from the config
// DOCUMENT itself, as opposed to correlated from syslog.
//
// A vendor that stamps the saving user into the file can be attributed with
// certainty and with no correlation window — no dependency on syslog reaching
// us, and no sensitivity to how long the backup took to arrive.
type ChangeAttribution struct {
	User        string // "root@192.168.5.15" or "(root)"
	Source      string // source IP, when the username carries one
	Method      string // GUI | API | "" when it cannot be determined
	Description string // the saving page, e.g. "/firewall_rules_edit.php made changes"
}

// ConfigAttributor is an optional capability a vendor Normalizer may implement.
//
// Implementations MUST read the RAW bytes of BOTH sides. Raw, because the
// normalizer masks the save-bookkeeping block precisely for churning on every
// save, so the attribution only exists before normalization. Both sides, because
// the stamp is trustworthy only when it ADVANCED — see the OPNsense
// implementation for why a wall-clock window is the wrong test.
type ConfigAttributor interface {
	AttributionFromConfig(cur, prev []byte) (ChangeAttribution, bool)
}

// AttributionFromConfig returns the in-config attribution for a vendor that
// records one, or ok=false so the caller can fall back to syslog correlation.
func AttributionFromConfig(vendor string, cur, prev []byte) (ChangeAttribution, bool) {
	a, ok := Lookup(vendor).(ConfigAttributor)
	if !ok {
		return ChangeAttribution{}, false
	}
	return a.AttributionFromConfig(cur, prev)
}

// HasConfigAttribution reports whether the vendor records attribution in-config.
func HasConfigAttribution(vendor string) bool {
	_, ok := Lookup(vendor).(ConfigAttributor)
	return ok
}

var (
	opnRevisionBlockRe = regexp.MustCompile(`(?s)<revision>(.*?)</revision>`)
	opnRevUsernameRe   = regexp.MustCompile(`<username>([^<]*)</username>`)
	opnRevDescRe       = regexp.MustCompile(`<description>([^<]*)</description>`)
	opnRevTimeRe       = regexp.MustCompile(`<time>([^<]*)</time>`)
)

// AttributionFromConfig reads OPNsense's top-level <revision> block, which
// records the user, the saving page and the save time for every GUI/API change.
//
// The block is accepted ONLY when its <time> ADVANCED relative to the previous
// config. That gate is the whole point, and the obvious alternative is wrong in
// both directions:
//
//   - Without a gate, attribution always succeeds (every config has a revision
//     block), so the out-of-band escalation is permanently disabled — and a
//     hand-edited config.xml + reload, which does NOT rewrite <revision>,
//     inherits the previous legitimate admin's stale block. That is active
//     misattribution, worse than none.
//
//   - With a wall-clock window instead ("the stamp must be recent"), a
//     legitimate change fails whenever delivery is slow: the window would be
//     measured at DB-write time while the collector's config poll defaults to 15
//     minutes, and production revision-to-delivery gaps already reach 12.9
//     minutes. Every such change would escalate to critical — reintroducing the
//     bug this exists to fix.
//
// Advancement is immune to poll cadence, ticker jitter and in-order replay.
// Non-advancement — a restore-from-backup carrying an older block, a device
// clock step, or an out-of-order retry delivery — correctly yields ok=false, so
// the change is reported unattributed rather than credited to the wrong admin.
func (opnsenseNormalizer) AttributionFromConfig(cur, prev []byte) (ChangeAttribution, bool) {
	// A prev row is guaranteed at the only call site (attribution runs solely on
	// an insert-change, which implies a previous revision), but never rely on a
	// caller's invariant for a security decision.
	if len(prev) == 0 {
		return ChangeAttribution{}, false
	}

	curBlock, curOK := opnRevisionBlock(cur)
	prevBlock, prevOK := opnRevisionBlock(prev)
	if !curOK {
		return ChangeAttribution{}, false
	}
	// Fail closed when the previous capture has no parsable block (a truncated or
	// garbage revision): the alternative credits a possible hand-edit to whoever
	// last saved legitimately, which is the misattribution this gate prevents.
	// The cost is one unattributed change after a bad capture — visible and
	// self-limiting, where a silent misattribution is neither.
	if !prevOK {
		return ChangeAttribution{}, false
	}
	if !(curBlock.time > prevBlock.time) {
		return ChangeAttribution{}, false
	}

	att := ChangeAttribution{User: curBlock.user, Description: curBlock.description}
	if i := strings.LastIndex(curBlock.user, "@"); i >= 0 {
		att.Source = curBlock.user[i+1:]
	}
	switch {
	case strings.Contains(curBlock.description, ".php"):
		att.Method = "GUI"
	case strings.Contains(curBlock.description, "/api/"):
		att.Method = "API"
	}
	// Otherwise Method stays empty. The corpus's most common description is
	// "Updated plugin interface configuration" — our own provisioner's API
	// change, matching neither pattern — so a catch-all "CLI" would mislabel the
	// single most frequent change source on the box.
	return att, att.User != ""
}

type opnRevision struct {
	user        string
	description string
	time        float64
}

func opnRevisionBlock(raw []byte) (opnRevision, bool) {
	m := opnRevisionBlockRe.FindSubmatch(raw)
	if m == nil {
		return opnRevision{}, false
	}
	body := string(m[1])

	var rev opnRevision
	if u := opnRevUsernameRe.FindStringSubmatch(body); u != nil {
		rev.user = strings.TrimSpace(u[1])
	}
	if d := opnRevDescRe.FindStringSubmatch(body); d != nil {
		rev.description = strings.TrimSpace(d[1])
	}
	t := opnRevTimeRe.FindStringSubmatch(body)
	if t == nil {
		return opnRevision{}, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(t[1]), 64)
	if err != nil {
		return opnRevision{}, false
	}
	rev.time = v
	return rev, true
}
