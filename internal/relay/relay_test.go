package relay

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestSchemaVersionBounds locks the handshake-constant invariants. These MUST
// stay in lockstep with the Firewall-Collector repo; a bad edit here (Min > Max,
// or a non-positive floor) would make the server reject every probe with HTTP
// 426 or accept versions it can't speak.
func TestSchemaVersionBounds(t *testing.T) {
	if SchemaVersionMin < 1 {
		t.Errorf("SchemaVersionMin = %d, must be >= 1", SchemaVersionMin)
	}
	if SchemaVersionMin > SchemaVersionMax {
		t.Errorf("SchemaVersionMin (%d) > SchemaVersionMax (%d)", SchemaVersionMin, SchemaVersionMax)
	}
}

// TestRegistrationSchemaVersionOmitempty pins the pre-handshake compatibility
// contract: a zero SchemaVersion must NOT appear on the wire (so already-deployed
// collectors that omit it keep working), while an explicit version must.
func TestRegistrationSchemaVersionOmitempty(t *testing.T) {
	t.Run("request omits zero version", func(t *testing.T) {
		b, err := json.Marshal(RegistrationRequest{RegistrationKey: "k", ProbeName: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "schema_version") {
			t.Errorf("zero SchemaVersion must be omitted; got %s", b)
		}
	})
	t.Run("request includes explicit version", func(t *testing.T) {
		b, _ := json.Marshal(RegistrationRequest{RegistrationKey: "k", SchemaVersion: SchemaVersionMax})
		if !strings.Contains(string(b), fmt.Sprintf(`"schema_version":%d`, SchemaVersionMax)) {
			t.Errorf("explicit SchemaVersion must be present; got %s", b)
		}
	})
	t.Run("response omits zero version", func(t *testing.T) {
		b, _ := json.Marshal(RegistrationResponse{Approved: true, ProbeID: 7})
		if strings.Contains(string(b), "schema_version") {
			t.Errorf("zero SchemaVersion must be omitted; got %s", b)
		}
	})
}

// TestFlowSampleDropsOmitempty pins the forward-compatibility contract for the
// v0.10.473 `drops` field: absent when zero so pre-adopting collectors see no
// new key.
func TestFlowSampleDropsOmitempty(t *testing.T) {
	zero, _ := json.Marshal(FlowSample{DeviceID: 1})
	if strings.Contains(string(zero), "drops") {
		t.Errorf("zero Drops must be omitted; got %s", zero)
	}
	nonzero, _ := json.Marshal(FlowSample{DeviceID: 1, Drops: 5})
	if !strings.Contains(string(nonzero), `"drops":5`) {
		t.Errorf("non-zero Drops must be present; got %s", nonzero)
	}
}

func TestHeartbeatObservedHostKeysOmitempty(t *testing.T) {
	b, _ := json.Marshal(HeartbeatRequest{ProbeID: 1, Status: "ok"})
	if strings.Contains(string(b), "observed_host_keys") {
		t.Errorf("nil ObservedHostKeys must be omitted; got %s", b)
	}
	b, _ = json.Marshal(HeartbeatRequest{ProbeID: 1, ObservedHostKeys: map[uint]string{2: "ssh-ed25519 AAAA"}})
	if !strings.Contains(string(b), "observed_host_keys") {
		t.Errorf("populated ObservedHostKeys must be present; got %s", b)
	}
}

// TestWireContractRoundTrip confirms the high-volume telemetry DTOs survive a
// marshal→unmarshal round-trip unchanged — locking the JSON tag names the
// collector depends on.
func TestWireContractRoundTrip(t *testing.T) {
	fs := FlowSample{
		DeviceID: 3, ProbeID: 4, SamplerAddress: "10.0.0.1",
		SrcAddr: "1.2.3.4", DstAddr: "5.6.7.8", SrcPort: 1024, DstPort: 443,
		Protocol: 6, Bytes: 1500, Packets: 2, SamplingRate: 512, Drops: 9,
	}
	var got FlowSample
	b, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got != fs {
		t.Errorf("round-trip mismatch:\n got  %+v\n want %+v", got, fs)
	}
	// Spot-check the exact wire keys the collector encodes against.
	for _, key := range []string{`"src_addr"`, `"dst_addr"`, `"sampling_rate"`, `"tcp_flags"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("FlowSample JSON missing expected key %s", key)
		}
	}
}
