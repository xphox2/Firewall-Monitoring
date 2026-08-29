package configdiff

import (
	"strings"
	"testing"
)

// Two OPNsense children with byte-identical {description, local_ts, remote_ts}
// collide on their keyed identity, so the walker appends a synthetic suffix to
// disambiguate them. AUDIT-264: that suffix used to be the GLOBAL emission
// ordinal (len(p.out)+1), so any unrelated object emitted earlier in snapshot B
// shifted the colliding child's synthetic Path — and DiffObjects, which keys
// strictly on Path, then reported the semantically-unchanged child as
// removed+added.
//
// Snapshot B differs from A only by an unrelated extra <Connection> emitted
// before the children. The colliding child's Path must stay stable, so the only
// object change is that added Connection.
const opnColliderA = `<?xml version="1.0"?>
<opnsense>
  <OPNsense>
    <Swanctl version="1.0.0" persisted_at="1785449420.74">
      <Connections>
        <Connection uuid="11111111-1111-1111-1111-111111111111">
          <description>conn-a</description>
          <proposals>aes256-sha256-modp2048</proposals>
        </Connection>
      </Connections>
      <children>
        <child uuid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa">
          <connection>11111111-1111-1111-1111-111111111111</connection>
          <local_ts>10.0.50.0/24</local_ts>
          <remote_ts>10.0.60.0/24</remote_ts>
          <description>dup-child</description>
        </child>
        <child uuid="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb">
          <connection>11111111-1111-1111-1111-111111111111</connection>
          <local_ts>10.0.50.0/24</local_ts>
          <remote_ts>10.0.60.0/24</remote_ts>
          <description>dup-child</description>
        </child>
      </children>
    </Swanctl>
  </OPNsense>
</opnsense>`

// opnColliderB: identical children, plus one unrelated Connection inserted
// EARLIER in the walk (Connections are emitted before children), which shifts
// the global emission ordinal for the colliding child.
const opnColliderB = `<?xml version="1.0"?>
<opnsense>
  <OPNsense>
    <Swanctl version="1.0.0" persisted_at="1785449999.99">
      <Connections>
        <Connection uuid="11111111-1111-1111-1111-111111111111">
          <description>conn-a</description>
          <proposals>aes256-sha256-modp2048</proposals>
        </Connection>
        <Connection uuid="22222222-2222-2222-2222-222222222222">
          <description>conn-unrelated</description>
          <proposals>aes256-sha256-modp2048</proposals>
        </Connection>
      </Connections>
      <children>
        <child uuid="cccccccc-cccc-cccc-cccc-cccccccccccc">
          <connection>11111111-1111-1111-1111-111111111111</connection>
          <local_ts>10.0.50.0/24</local_ts>
          <remote_ts>10.0.60.0/24</remote_ts>
          <description>dup-child</description>
        </child>
        <child uuid="dddddddd-dddd-dddd-dddd-dddddddddddd">
          <connection>11111111-1111-1111-1111-111111111111</connection>
          <local_ts>10.0.50.0/24</local_ts>
          <remote_ts>10.0.60.0/24</remote_ts>
          <description>dup-child</description>
        </child>
      </children>
    </Swanctl>
  </OPNsense>
</opnsense>`

func TestOPNsenseSyntheticPathStableUnderInsertion_AUDIT264(t *testing.T) {
	t.Parallel()

	// Precondition: the colliding children really do produce a synthetic
	// "#"-suffixed Path (otherwise the test proves nothing).
	objsA, ok := ParseObjects("opnsense", parseInputFor("opnsense", []byte(opnColliderA)))
	if !ok {
		t.Fatal("ParseObjects returned ok=false for opnsense")
	}
	var childPaths []string
	sawSuffix := false
	for _, o := range objsA {
		if o.Kind == "OPNsense.Swanctl.children.child" {
			childPaths = append(childPaths, o.Path)
			if strings.Contains(o.Path, "#") {
				sawSuffix = true
			}
		}
	}
	if len(childPaths) != 2 {
		t.Fatalf("expected 2 child objects, got %d (%v)", len(childPaths), childPaths)
	}
	if !sawSuffix {
		t.Fatalf("colliding children did not produce a synthetic suffix — test cannot exercise AUDIT-264 (paths: %v)", childPaths)
	}

	// The colliding child's Path must be identical across snapshots even though
	// B emits an unrelated Connection first. So the ONLY change is that added
	// Connection — no child appears as removed or added.
	changes, ok := DiffObjects("opnsense", []byte(opnColliderA), []byte(opnColliderB))
	if !ok {
		t.Fatal("DiffObjects returned ok=false for opnsense")
	}
	for _, c := range changes {
		if strings.HasPrefix(c.Kind, "OPNsense.Swanctl.children.child") && (c.Op == "removed" || c.Op == "added") {
			t.Errorf("spurious child churn (AUDIT-264): %s %s %v", c.Op, c.Path, c.Attrs)
		}
	}

	// Sanity: the unrelated Connection IS reported added, proving the diff ran.
	sawConnAdd := false
	for _, c := range changes {
		if c.Op == "added" && strings.Contains(c.Path, "conn-unrelated") {
			sawConnAdd = true
		}
	}
	if !sawConnAdd {
		var got []string
		for _, c := range changes {
			got = append(got, c.Op+" "+c.Path)
		}
		t.Errorf("expected the unrelated Connection to diff as added; changes=%v", got)
	}
}
