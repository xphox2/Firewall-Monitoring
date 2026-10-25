package database

import (
	"reflect"
	"strings"
	"testing"
)

// L-18: every partition name purgeRelations reads from pg_inherits is spliced
// into batchedDeleteWhere's DELETE, so a name outside safeRelName's shape must
// fail the enumeration (and with it the job) instead of reaching the SQL.
func TestOrderPurgeChildren_RefusesUnsafeRelName(t *testing.T) {
	for _, name := range []string{
		`syslog_messages_202601; DROP TABLE devices`,
		`syslog_messages "x"`,
		`public.syslog_messages_202601`,
		``,
	} {
		children := []purgeChild{
			{Name: "syslog_messages_202602", Bound: "FOR VALUES FROM ('2026-02-01') TO ('2026-03-01')"},
			{Name: name, Bound: "FOR VALUES FROM ('2026-01-01') TO ('2026-02-01')"},
		}
		out, err := orderPurgeChildren("syslog_messages", children)
		if err == nil {
			t.Fatalf("name %q: want refusal, got relations %v", name, out)
		}
		if !strings.Contains(err.Error(), "refusing partition name") {
			t.Fatalf("name %q: unexpected error %v", name, err)
		}
	}
}

// The guard must not change the ordering contract: oldest range first, the
// DEFAULT child (unparseable bound) last, an empty parent → the parent itself.
func TestOrderPurgeChildren_OrdersSafeNames(t *testing.T) {
	children := []purgeChild{
		{Name: "syslog_messages_default", Bound: "DEFAULT"},
		{Name: "syslog_messages_202602", Bound: "FOR VALUES FROM ('2026-02-01') TO ('2026-03-01')"},
		{Name: "syslog_messages_202601", Bound: "FOR VALUES FROM ('2026-01-01') TO ('2026-02-01')"},
	}
	out, err := orderPurgeChildren("syslog_messages", children)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"syslog_messages_202601", "syslog_messages_202602", "syslog_messages_default"}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
	if out, err := orderPurgeChildren("syslog_messages", nil); err != nil || !reflect.DeepEqual(out, []string{"syslog_messages"}) {
		t.Fatalf("empty parent: got %v, %v", out, err)
	}
}
