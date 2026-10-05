package normalize

import (
	"reflect"
	"testing"
)

// TestNormalizeFramed_MatchesNormalize: for every fixture a 1.3.48+ collector
// would ship (a non-empty format hint — the framing contract a v6 probe
// guarantees per row), NormalizeFramed, which tokenizes Message alone, must
// produce exactly what Normalize produces through the re-framing join. Every
// format the collector's dispatcher emits must be covered, so that no family
// quietly depends on the join (a BSD tag, a 5424 app name) for a correctly
// framed row. Fixtures without a hint are the pre-1.3.48 positional splits
// and are what the join is for; they are excluded here and exercised by the
// goldens and the handler test.
func TestNormalizeFramed_MatchesNormalize(t *testing.T) {
	t.Parallel()
	want := map[string]bool{"fortios_kv": false, "rfc3164": false, "rfc5424": false, "meraki": false, "cef": false, "raw": false}
	n := 0
	for _, vendor := range fixtureVendors(t) {
		for _, f := range loadFixtures(t, vendor) {
			if f.Msg.Format == "" {
				continue
			}
			if _, known := want[f.Msg.Format]; !known {
				t.Errorf("%s/%s: format %q is not one the collector dispatcher emits", vendor, f.Name, f.Msg.Format)
				continue
			}
			want[f.Msg.Format] = true
			n++
			joined := run(vendor, f)
			msg := f.Msg
			ev, out := NormalizeFramed(vendor, &msg)
			framed := golden{Name: f.Name, Outcome: out.Kind.String(), Reason: out.Reason, Native: ev.Native}
			if out.Kind == OutcomeOK {
				framed.Event = map[string]string{}
				ev.Fields(framed.Event)
			}
			if !reflect.DeepEqual(joined, framed) {
				t.Errorf("%s/%s (%s): NormalizeFramed differs from Normalize\n joined: %+v\n framed: %+v", vendor, f.Name, f.Msg.Format, joined, framed)
			}
		}
	}
	for format, seen := range want {
		if !seen {
			t.Errorf("no fixture with format %q — every dispatcher format needs one framed fixture", format)
		}
	}
	if n < 60 {
		t.Errorf("only %d framed fixtures compared; expected the bulk of the corpus", n)
	}
}
