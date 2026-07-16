package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// Tests for the relay schema-v4 server→collector command channel at the HTTP
// layer: heartbeat-carried delivery gated on the probe's PERSISTED negotiated
// schema version, idempotent result ingest, register-time persistence of the
// negotiated version, and the noop-only admin enqueue.

// seedCommandProbe creates an approved probe with the given schema_version
// and returns it with the PLAINTEXT bearer key on RegistrationKey.
func seedCommandProbe(t *testing.T, db *database.Database, name string, schemaVersion int) *models.Probe {
	t.Helper()
	site := &models.Site{Name: name + "-site"}
	if err := db.Gorm().Create(site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}
	key := name + "-key"
	p := &models.Probe{
		Name:            name,
		SiteID:          site.ID,
		RegistrationKey: database.HashProbeKey(key),
		Enabled:         true,
		ApprovalStatus:  "approved",
		Status:          "online",
		SchemaVersion:   schemaVersion,
	}
	if err := db.Gorm().Create(p).Error; err != nil {
		t.Fatalf("create probe: %v", err)
	}
	p.RegistrationKey = key
	return p
}

func postHeartbeat(t *testing.T, h *Handler, key string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/api/probes/heartbeat", h.ProbeHeartbeat)
	body, _ := json.Marshal(map[string]any{"status": "online"})
	req := httptest.NewRequest("POST", "/api/probes/heartbeat", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestProbeHeartbeat_CommandsGatedOnSchemaV4 pins the compatibility gate: a
// probe whose PERSISTED negotiated schema is < 4 must never be sent
// pending_commands (and its queued commands must stay `pending`, not burn
// delivery attempts); a v4 probe gets them delivered and dispatched.
func TestProbeHeartbeat_CommandsGatedOnSchemaV4(t *testing.T) {
	h, db := setupTestHandler(t)

	// --- v3 probe: gate closed ---
	p3 := seedCommandProbe(t, db, "hb-cmd-v3", 3)
	cmd3 := &models.ProbeCommand{ProbeID: p3.ID, Type: "noop", Payload: `{"n":3}`}
	if err := db.EnqueueProbeCommand(cmd3); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	w := postHeartbeat(t, h, p3.RegistrationKey)
	if w.Code != http.StatusOK {
		t.Fatalf("v3 heartbeat = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp3 map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := resp3["pending_commands"]; ok {
		t.Error("v3 probe received pending_commands — the schema gate leaked a v4 wire field")
	}
	var stored models.ProbeCommand
	if err := db.Gorm().Where("command_id = ?", cmd3.CommandID).First(&stored).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored.Status != database.ProbeCommandStatusPending || stored.Attempts != 0 {
		t.Errorf("v3 probe's command = %s/attempts=%d, want pending/0 (no attempts burned below the gate)", stored.Status, stored.Attempts)
	}

	// --- v4 probe: gate open ---
	p4 := seedCommandProbe(t, db, "hb-cmd-v4", 4)
	cmd4 := &models.ProbeCommand{ProbeID: p4.ID, DeviceID: 42, Type: "noop", Payload: `{"n":4}`}
	if err := db.EnqueueProbeCommand(cmd4); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	w = postHeartbeat(t, h, p4.RegistrationKey)
	if w.Code != http.StatusOK {
		t.Fatalf("v4 heartbeat = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp4 struct {
		Success         bool `json:"success"`
		PendingCommands []struct {
			CommandID string `json:"command_id"`
			DeviceID  uint   `json:"device_id"`
			Type      string `json:"type"`
			Payload   string `json:"payload"`
		} `json:"pending_commands"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp4); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp4.PendingCommands) != 1 {
		t.Fatalf("v4 heartbeat carried %d command(s), want 1; body: %s", len(resp4.PendingCommands), w.Body.String())
	}
	got := resp4.PendingCommands[0]
	if got.CommandID != cmd4.CommandID || got.Type != "noop" || got.DeviceID != 42 || got.Payload != `{"n":4}` {
		t.Errorf("delivered command = %+v, want the enqueued noop with its plaintext payload", got)
	}
	// Fresh struct — reusing `stored` would leak its primary key into the
	// WHERE clause (GORM condition pollution).
	var stored4 models.ProbeCommand
	if err := db.Gorm().Where("command_id = ?", cmd4.CommandID).First(&stored4).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored4.Status != database.ProbeCommandStatusDispatched || stored4.Attempts != 1 {
		t.Errorf("delivered command = %s/attempts=%d, want dispatched/1", stored4.Status, stored4.Attempts)
	}

	// Second heartbeat: freshly-dispatched command must not be re-delivered.
	// (Fresh map — unmarshal into the used resp4 struct would keep the old
	// slice when the key is absent.)
	w = postHeartbeat(t, h, p4.RegistrationKey)
	var resp4b map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp4b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := resp4b["pending_commands"]; ok {
		t.Errorf("2nd heartbeat re-delivered commands before the redelivery window: %s", w.Body.String())
	}
}

// TestReceiveCommandResult_Idempotent exercises POST /probes/:id/command-result
// end to end: first result applies; a replay (collector retry or redelivery
// race) is a 200 no-op that keeps the FIRST result; unknown command_id is 404;
// invalid status is 400.
func TestReceiveCommandResult_Idempotent(t *testing.T) {
	h, db := setupTestHandler(t)
	p := seedCommandProbe(t, db, "cmdresult", 4)
	cmd := &models.ProbeCommand{ProbeID: p.ID, Type: "noop"}
	if err := db.EnqueueProbeCommand(cmd); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if got, _ := db.ClaimProbeCommands(p.ID); len(got) != 1 {
		t.Fatalf("claim: %d, want 1", len(got))
	}

	post := func(body map[string]any) *httptest.ResponseRecorder {
		return doTestRequest(t, h.ReceiveCommandResult, "POST", "/command-result", p.ID, p.RegistrationKey, body)
	}

	w := post(map[string]any{"command_id": cmd.CommandID, "status": "succeeded", "result": "noop ok"})
	if w.Code != http.StatusOK {
		t.Fatalf("first result = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Replay with a CONFLICTING status: 200 (idempotent no-op), first result kept.
	w = post(map[string]any{"command_id": cmd.CommandID, "status": "failed", "result": "late duplicate"})
	if w.Code != http.StatusOK {
		t.Fatalf("replayed result = %d, want 200 (idempotent); body: %s", w.Code, w.Body.String())
	}
	var stored models.ProbeCommand
	if err := db.Gorm().Where("command_id = ?", cmd.CommandID).First(&stored).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored.Status != database.ProbeCommandStatusSucceeded || stored.Result != "noop ok" {
		t.Errorf("stored = %s/%q, want the FIRST result (succeeded/\"noop ok\")", stored.Status, stored.Result)
	}

	if w := post(map[string]any{"command_id": "no-such-command", "status": "succeeded"}); w.Code != http.StatusNotFound {
		t.Errorf("unknown command_id = %d, want 404", w.Code)
	}
	if w := post(map[string]any{"command_id": cmd.CommandID, "status": "running"}); w.Code != http.StatusBadRequest {
		t.Errorf("invalid status = %d, want 400", w.Code)
	}
	if w := post(map[string]any{"status": "succeeded"}); w.Code != http.StatusBadRequest {
		t.Errorf("missing command_id = %d, want 400", w.Code)
	}
}

// TestReceiveCommandResult_NoopDoesNotBumpLastPolled pins the gate on the
// command-result reachability bump: a succeeded command only bumps the target
// device's last_polled when its type actually contacts the device
// (ProbeCommandTouchesDevice). noop completes inside the collector without
// touching any device, so even a succeeded device-targeted noop must leave
// last_polled and status alone. (No device-touching type exists yet — IPSec
// apply will be the first — so the positive path is unreachable end-to-end;
// the gate's truth table is pinned in internal/database.)
func TestReceiveCommandResult_NoopDoesNotBumpLastPolled(t *testing.T) {
	h, db := setupTestHandler(t)
	p := seedCommandProbe(t, db, "cmdbump", 4)
	device := &models.Device{Name: "cmdbump-fw", IPAddress: "192.168.7.7", ProbeID: &p.ID}
	if err := db.Gorm().Create(device).Error; err != nil {
		t.Fatalf("create device: %v", err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := db.Gorm().Model(&models.Device{}).Where("id = ?", device.ID).
		Updates(map[string]interface{}{"status": "offline", "last_polled": stale}).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}

	cmd := &models.ProbeCommand{ProbeID: p.ID, DeviceID: device.ID, Type: database.ProbeCommandTypeNoop}
	if err := db.EnqueueProbeCommand(cmd); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if got, _ := db.ClaimProbeCommands(p.ID); len(got) != 1 {
		t.Fatalf("claim: %d, want 1", len(got))
	}

	body := map[string]any{"command_id": cmd.CommandID, "status": "succeeded", "result": "noop ok"}
	if w := doTestRequest(t, h.ReceiveCommandResult, "POST", "/command-result", p.ID, p.RegistrationKey, body); w.Code != http.StatusOK {
		t.Fatalf("result = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var dev models.Device
	if err := db.Gorm().First(&dev, device.ID).Error; err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if dev.Status != "offline" || dev.LastPolled.After(stale.Add(time.Minute)) {
		t.Errorf("succeeded noop bumped the device: status=%q last_polled=%v (want offline/%v)",
			dev.Status, dev.LastPolled, stale)
	}
}

// TestRegisterProbe_PersistsNegotiatedSchemaVersion pins M1 of the PR-1 plan:
// RegisterProbe must WRITE the selected schema_version onto the Probe row —
// including on the already-approved+online fast path (what a freshly-upgraded
// collector hits) — because the heartbeat command gate reads the stored value.
func TestRegisterProbe_PersistsNegotiatedSchemaVersion(t *testing.T) {
	h, db := setupTestHandler(t)

	register := func(key string, schemaVersion int) *httptest.ResponseRecorder {
		router := gin.New()
		router.POST("/api/probes/register", h.RegisterProbe)
		body, _ := json.Marshal(map[string]any{"registration_key": key, "schema_version": schemaVersion})
		req := httptest.NewRequest("POST", "/api/probes/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// Fresh (pending/offline) probe: the main register path must persist v4.
	key := "register-schema-key"
	p := &models.Probe{
		Name:            "register-schema-probe",
		RegistrationKey: database.HashProbeKey(key),
		Enabled:         true,
		ApprovalStatus:  "pending",
		Status:          "offline",
	}
	if err := db.Gorm().Create(p).Error; err != nil {
		t.Fatalf("seed probe: %v", err)
	}

	if w := register(key, 4); w.Code != http.StatusOK {
		t.Fatalf("register = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var stored models.Probe
	db.Gorm().First(&stored, p.ID)
	if stored.SchemaVersion != 4 {
		t.Fatalf("stored schema_version = %d after register, want 4", stored.SchemaVersion)
	}

	// Already approved+online (the fast path): a re-register with a DIFFERENT
	// version must still update the row — this is what an upgraded (or
	// downgraded) collector hits.
	if w := register(key, 3); w.Code != http.StatusOK {
		t.Fatalf("re-register = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	db.Gorm().First(&stored, p.ID)
	if stored.SchemaVersion != 3 {
		t.Errorf("stored schema_version = %d after re-register, want 3 (fast path must persist too)", stored.SchemaVersion)
	}
}

// TestCreateProbeCommand_NoopOnly pins the PR-1 admin enqueue surface: only
// the `noop` type is accepted, the response returns the command_id (never the
// payload), and the queued row is pending with an expiry.
func TestCreateProbeCommand_NoopOnly(t *testing.T) {
	h, db := setupTestHandler(t)
	p := seedCommandProbe(t, db, "admin-enqueue", 4)

	post := func(body map[string]any) *httptest.ResponseRecorder {
		router := gin.New()
		router.POST("/admin/api/probes/:id/commands", h.CreateProbeCommand)
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", fmt.Sprintf("/admin/api/probes/%d/commands", p.ID), bytes.NewBuffer(b))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if w := post(map[string]any{"type": "apply_ipsec"}); w.Code != http.StatusBadRequest {
		t.Errorf("non-noop enqueue = %d, want 400 (PR-1 allow-list)", w.Code)
	}

	w := post(map[string]any{"type": "noop", "payload": `{"secret":"x"}`})
	if w.Code != http.StatusOK {
		t.Fatalf("noop enqueue = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte(`"secret"`)) {
		t.Error("enqueue response echoed the payload — payloads must never be returned")
	}
	var resp struct {
		Data struct {
			CommandID string `json:"command_id"`
			Status    string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.CommandID == "" || resp.Data.Status != database.ProbeCommandStatusPending {
		t.Errorf("enqueue response = %+v, want a command_id and pending status", resp.Data)
	}

	// The admin list endpoint must not leak payloads either (json:"-").
	router := gin.New()
	router.GET("/admin/api/probes/:id/commands", h.GetProbeCommands)
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/api/probes/%d/commands", p.ID), nil)
	lw := httptest.NewRecorder()
	router.ServeHTTP(lw, req)
	if lw.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200; body: %s", lw.Code, lw.Body.String())
	}
	if bytes.Contains(lw.Body.Bytes(), []byte("secret")) || bytes.Contains(lw.Body.Bytes(), []byte("payload")) {
		t.Error("admin command list leaked the payload — ProbeCommand.Payload must stay json:\"-\"")
	}
}
