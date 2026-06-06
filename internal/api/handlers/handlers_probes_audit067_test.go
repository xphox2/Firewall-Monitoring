package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// seedProbe writes a probe with the given plaintext key, hashing it at rest
// per AUDIT-017. It returns the probe (with the plaintext key re-set on the
// returned struct, matching setupProbeAndDevice's convention) so the caller can
// pass the plaintext into the Authorization header.
func seedProbe(t *testing.T, db *database.Database, name, tenantID, plainKey string) *models.Probe {
	t.Helper()
	probe := &models.Probe{
		Name:            name,
		TenantID:        tenantID,
		RegistrationKey: database.HashProbeKey(plainKey),
		ApprovalStatus:  "approved",
		Status:          "online",
	}
	if err := db.Gorm().Create(probe).Error; err != nil {
		t.Fatalf("seed probe %s: %v", name, err)
	}
	probe.RegistrationKey = plainKey // restore plaintext for the caller
	return probe
}

// TestToken_UsedCrossTenant_Returns403_AUDIT067 verifies the cross-tenant
// 403 contract:
//  1. A token issued for tenant A cannot access a probe in tenant B — the
//     server returns 403, not 401 (the codes are semantically distinct:
//     401 = "token is wrong for this probe", 403 = "you are not allowed
//     in this tenant").
//  2. The audit log records the attempt with the TARGET probe's tenant
//     (so a forensic query "show me every attempt against tenant B" finds
//     it).
//  3. A token issued for tenant A STILL works against other probes in
//     tenant A (the check is per-tenant, not per-probe — different probes
//     in the same tenant authenticate independently because each has its
//     own key).
func TestToken_UsedCrossTenant_Returns403_AUDIT067(t *testing.T) {
	h, db := setupTestHandler(t)

	tenantAKey := "tenant-A-probe-key-001"
	tenantBKey := "tenant-B-probe-key-001"
	probeA := seedProbe(t, db, "probe-a", "tenant-A", tenantAKey)
	probeB := seedProbe(t, db, "probe-b", "tenant-B", tenantBKey)

	// post: hit the syslog endpoint for the given probe ID, with the given
	// bearer token. The route is registered with the `:id` placeholder
	// pattern so validateProbe can extract the URL parameter; the actual
	// probe ID is interpolated into the request URL.
	post := func(targetProbeID uint, token string) *httptest.ResponseRecorder {
		router := gin.New()
		router.POST("/api/probes/:id/syslog", h.ReceiveSyslogMessages)
		body, _ := json.Marshal([]models.SyslogMessage{{Message: "x", SourceIP: "10.0.0.1"}})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/syslog", targetProbeID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// Case 1: probe-A token → probe-B URL → 403.
	w := post(probeB.ID, tenantAKey)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-tenant (A→B): status=%d, want 403; body=%s", w.Code, w.Body.String())
	}

	// Case 2: probe-B token → probe-A URL → 403 (symmetric).
	w = post(probeA.ID, tenantBKey)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-tenant (B→A): status=%d, want 403; body=%s", w.Code, w.Body.String())
	}

	// Case 3: probe-A token → probe-A URL → 200 (same-tenant, correct key).
	w = post(probeA.ID, tenantAKey)
	if w.Code != http.StatusOK {
		t.Errorf("same-tenant (A→A): status=%d, want 200; body=%s", w.Code, w.Body.String())
	}

	// Case 4: wrong key for own tenant → 401 (NOT 403). Same-tenant wrong-key
	// is "you sent the wrong token", which is semantically a 401, not a
	// cross-tenant attempt.
	w = post(probeA.ID, "garbage-token")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("same-tenant wrong key: status=%d, want 401; body=%s", w.Code, w.Body.String())
	}

	// Audit-log assertions: every attempt above must have produced exactly
	// one probe_token_audits row, and the cross-tenant attempts must show
	// 403 with the target probe's tenant_id (so an operator can pivot by
	// tenant when investigating).
	var audits []models.ProbeTokenAudit
	if err := db.Gorm().Order("id ASC").Find(&audits).Error; err != nil {
		t.Fatalf("load audits: %v", err)
	}
	if len(audits) != 4 {
		t.Fatalf("expected 4 audit rows, got %d", len(audits))
	}
	// Each row's tenant_id is the TARGET probe's (i.e. the probe named in
	// the URL), not the source token's tenant — so the cross-tenant 403s
	// record the (probe-B, tenant-B) pair and the (probe-A, tenant-A) pair.
	// Use a slice-of-tuples (a map would dedupe probeA.ID across the three
	// cases that share the target).
	type want struct {
		probeID  uint
		tenantID string
		status   int
	}
	wantFor := []want{
		{probeB.ID, "tenant-B", http.StatusForbidden},    // case 1: cross-tenant
		{probeA.ID, "tenant-A", http.StatusForbidden},    // case 2: cross-tenant
		{probeA.ID, "tenant-A", http.StatusOK},           // case 3: same-tenant OK
		{probeA.ID, "tenant-A", http.StatusUnauthorized}, // case 4: wrong key
	}
	if len(wantFor) != len(audits) {
		t.Fatalf("len(wantFor)=%d, len(audits)=%d", len(wantFor), len(audits))
	}
	for i, a := range audits {
		w := wantFor[i]
		if a.ProbeID != w.probeID {
			t.Errorf("audit[%d]: probe_id=%d, want %d", i, a.ProbeID, w.probeID)
		}
		if a.TenantID != w.tenantID {
			t.Errorf("audit[%d] probe_id=%d: tenant_id=%q, want %q", i, a.ProbeID, a.TenantID, w.tenantID)
		}
		if a.StatusCode != w.status {
			t.Errorf("audit[%d] probe_id=%d: status_code=%d, want %d", i, a.ProbeID, a.StatusCode, w.status)
		}
		if a.Method != "POST" {
			t.Errorf("audit[%d]: method=%q, want POST", i, a.Method)
		}
	}
}

// TestToken_AuditLog_RecordsEveryRequest_AUDIT067 verifies the audit log
// fires on EVERY authenticated probe request, success or failure. The
// collector's hot path is one POST per device-data-type per poll cycle
// (syslog/traps/flows/pings + heartbeat); if any of those don't produce an
// audit row, a stolen token's usage pattern is incomplete.
//
// Strategy: hit several distinct probe endpoints in sequence and assert
// that one audit row per call was written, with the correct probe_id,
// tenant_id, and endpoint.
func TestToken_AuditLog_RecordsEveryRequest_AUDIT067(t *testing.T) {
	h, db := setupTestHandler(t)
	const plainKey = "audit-test-probe-key"
	probe := seedProbe(t, db, "audit-probe", "tenant-X", plainKey)

	type endpoint struct {
		method string
		path   string
		// handler registered as the route's terminal handler.
		bind func(r *gin.Engine)
		body interface{}
	}
	calls := []endpoint{
		{
			method: "POST",
			path:   fmt.Sprintf("/api/probes/%d/heartbeat", probe.ID),
			bind: func(r *gin.Engine) {
				r.POST("/api/probes/:id/heartbeat", h.ProbeHeartbeat)
			},
			body: map[string]interface{}{"probe_id": probe.ID, "status": "online"},
		},
		{
			method: "POST",
			path:   fmt.Sprintf("/api/probes/%d/syslog", probe.ID),
			bind: func(r *gin.Engine) {
				r.POST("/api/probes/:id/syslog", h.ReceiveSyslogMessages)
			},
			body: []models.SyslogMessage{{Message: "audit-test", SourceIP: "10.0.0.1"}},
		},
		{
			method: "GET",
			path:   fmt.Sprintf("/api/probes/%d/devices", probe.ID),
			bind: func(r *gin.Engine) {
				r.GET("/api/probes/:id/devices", h.GetProbeDevices)
			},
			body: nil,
		},
	}

	// Hit each endpoint. Audit rows accumulate; check at the end that we
	// have exactly len(calls) successful (2xx) audit entries for this probe.
	for _, ep := range calls {
		router := gin.New()
		ep.bind(router)
		var bodyBytes []byte
		if ep.body != nil {
			bodyBytes, _ = json.Marshal(ep.body)
		}
		req := httptest.NewRequest(ep.method, ep.path, bytes.NewReader(bodyBytes))
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+plainKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("call %s %s: status=%d body=%s", ep.method, ep.path, w.Code, w.Body.String())
		}
	}

	var audits []models.ProbeTokenAudit
	if err := db.Gorm().Where("probe_id = ?", probe.ID).Order("id ASC").Find(&audits).Error; err != nil {
		t.Fatalf("load audits: %v", err)
	}
	if len(audits) != len(calls) {
		t.Fatalf("expected %d audit rows for probe %d, got %d", len(calls), probe.ID, len(audits))
	}
	for i, a := range audits {
		if a.TenantID != "tenant-X" {
			t.Errorf("audit[%d]: tenant_id=%q, want tenant-X", i, a.TenantID)
		}
		if a.StatusCode < 200 || a.StatusCode >= 300 {
			t.Errorf("audit[%d]: status_code=%d, want 2xx", i, a.StatusCode)
		}
		if a.Endpoint == "" {
			t.Errorf("audit[%d]: empty endpoint", i)
		}
		if a.Method == "" {
			t.Errorf("audit[%d]: empty method", i)
		}
		if a.RemoteIP == "" {
			t.Errorf("audit[%d]: empty remote_ip (httptest server records a 127.0.0.0/8 IP)", i)
		}
		if a.Timestamp.IsZero() {
			t.Errorf("audit[%d]: zero timestamp", i)
		}
	}

	// Cross-tenant attempts ALSO produce audit rows. Drive one to confirm
	// the failure path is logged (the v0.10.335 audit-flag fix was exactly
	// that: a stolen token's 401/403 failures were missing from the
	// timeline, so the operator could not see "attacker tried this token
	// 1000 times before getting the right URL").
	other := seedProbe(t, db, "other-tenant", "tenant-Y", "other-tenant-key")
	{
		router := gin.New()
		router.POST("/api/probes/:id/syslog", h.ReceiveSyslogMessages)
		body, _ := json.Marshal([]models.SyslogMessage{{Message: "x", SourceIP: "10.0.0.1"}})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/syslog", other.ID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+plainKey) // tenant-X token at tenant-Y URL
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-tenant: status=%d, want 403; body=%s", w.Code, w.Body.String())
		}
	}

	// Verify the new (cross-tenant) audit row was recorded under the
	// TARGET probe (probeB.ID, tenant-Y) with status 403. The original
	// "for this probe" rows (probe.ID, tenant-X) are unaffected.
	var xTenant []models.ProbeTokenAudit
	if err := db.Gorm().Where("probe_id = ? AND tenant_id = ? AND status_code = ?",
		other.ID, "tenant-Y", http.StatusForbidden).Find(&xTenant).Error; err != nil {
		t.Fatalf("load x-tenant audits: %v", err)
	}
	if len(xTenant) != 1 {
		t.Errorf("expected 1 cross-tenant audit row for probe %d tenant-Y 403, got %d", other.ID, len(xTenant))
	}
}

// TestToken_Rotation_AllowsGracePeriod_AUDIT067 documents the rotation
// status as of v0.10.363: server-side rotation is provided by
// RegenerateProbeKey (AUDIT-085), which atomically swaps the stored key.
//
// The original AUDIT-067 spec called for a 24h grace period in which the OLD
// key continues to authenticate after rotation. **That grace period is NOT
// implemented in v0.10.363** — it is explicitly deferred. The current
// behavior is "rotation is immediate; the old key stops working as soon as
// RegenerateProbeKey commits." The collector's `tryReregister` path
// (relay.go:489-525 in the collector repo) handles the immediate-revocation
// case by re-registering on a 401, picking up the new key, and continuing.
//
// This test pins the *current* contract so a future implementer doesn't
// silently change it: (a) the new key authenticates immediately, (b) the
// OLD key stops working immediately (no grace period), (c) the audit log
// captures both the pre- and post-rotation successful auths, and (d) the
// rotation itself is a single transaction (re-asserted from AUDIT-085; we
// re-verify the keys-on-disk state is consistent).
//
// When the deferred grace-period work lands, this test will be updated to
// also assert that the OLD key continues to authenticate for the grace
// window — that addition will replace (b) above.
func TestToken_Rotation_AllowsGracePeriod_AUDIT067(t *testing.T) {
	h, db := setupTestHandler(t)
	if err := db.Gorm().AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate system_settings: %v", err)
	}
	const oldKey = "rotation-old-key-001"
	probe := seedProbe(t, db, "rotation-probe", "tenant-Z", oldKey)
	// SystemSetting that mirrors the hashed key, so RegisterProbe lookup
	// works (it is the same auth-by-registration-key path).
	if err := db.Gorm().Create(&models.SystemSetting{
		Key:      "probe_registration_" + database.HashProbeKey(oldKey),
		Value:    probe.Name,
		Type:     "string",
		Category: "probes",
	}).Error; err != nil {
		t.Fatalf("seed registration setting: %v", err)
	}

	// Pre-rotation: the OLD key authenticates successfully.
	{
		router := gin.New()
		router.POST("/api/probes/:id/heartbeat", h.ProbeHeartbeat)
		body, _ := json.Marshal(map[string]interface{}{"probe_id": probe.ID, "status": "online"})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/heartbeat", probe.ID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+oldKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("pre-rotation heartbeat: status=%d body=%s", w.Code, w.Body.String())
		}
	}

	// Rotate.
	router := gin.New()
	router.POST("/api/probes/:id/regenerate-key", h.RegenerateProbeKey)
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/regenerate-key", probe.ID), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("regenerate: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			RegistrationKey string `json:"registration_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	newKey := resp.Data.RegistrationKey
	if newKey == "" || newKey == oldKey {
		t.Fatalf("rotate did not produce a fresh key (got %q)", newKey)
	}

	// Post-rotation: the NEW key authenticates.
	{
		router := gin.New()
		router.POST("/api/probes/:id/heartbeat", h.ProbeHeartbeat)
		body, _ := json.Marshal(map[string]interface{}{"probe_id": probe.ID, "status": "online"})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/heartbeat", probe.ID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+newKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("post-rotation heartbeat (NEW key): status=%d body=%s, want 200", w.Code, w.Body.String())
		}
	}

	// Post-rotation: the OLD key is REJECTED. This is the v0.10.363
	// behavior (no grace period). When the deferred grace-period work
	// lands, this assertion will be replaced with: "OLD key still
	// authenticates for the grace window, then expires."
	{
		router := gin.New()
		router.POST("/api/probes/:id/heartbeat", h.ProbeHeartbeat)
		body, _ := json.Marshal(map[string]interface{}{"probe_id": probe.ID, "status": "online"})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/heartbeat", probe.ID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+oldKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("post-rotation heartbeat (OLD key): status=%d body=%s, want 401 (grace period not yet implemented — see AUDIT-067 deferred work)", w.Code, w.Body.String())
		}
	}

	// Audit log captured every authentication outcome in this scenario:
	// pre-rotation success, post-rotation-new-key success, and the
	// post-rotation-old-key failure (which has probe_id=0, tenant_id=""
	// because the OLD token doesn't resolve to any probe). Two rows match
	// the (probe.ID, tenant-Z) filter, and the third exists with
	// anonymous identity.
	var audits []models.ProbeTokenAudit
	if err := db.Gorm().Where("probe_id = ? AND tenant_id = ?", probe.ID, "tenant-Z").
		Order("id ASC").Find(&audits).Error; err != nil {
		t.Fatalf("load audits: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("expected 2 audit rows tagged to the rotation probe+tenant, got %d", len(audits))
	}
	if audits[0].StatusCode != http.StatusOK {
		t.Errorf("audit[0] (pre-rotate OLD): status=%d, want 200", audits[0].StatusCode)
	}
	if audits[1].StatusCode != http.StatusOK {
		t.Errorf("audit[1] (post-rotate NEW): status=%d, want 200", audits[1].StatusCode)
	}
	// Third row: the rejected OLD-key attempt. probe_id=0 / tenant_id=""
	// because the token doesn't resolve to any probe after rotation; only
	// its remote IP, method, and 401 status are recorded.
	var rejected []models.ProbeTokenAudit
	if err := db.Gorm().Where("probe_id = ? AND status_code = ?", uint(0), http.StatusUnauthorized).
		Order("id ASC").Find(&rejected).Error; err != nil {
		t.Fatalf("load rejected audits: %v", err)
	}
	if len(rejected) != 1 {
		t.Fatalf("expected 1 anonymous (probe_id=0) 401 audit row from the rejected OLD key, got %d", len(rejected))
	}
	if rejected[0].Method != "POST" || rejected[0].Endpoint == "" {
		t.Errorf("rejected audit row malformed: method=%q endpoint=%q", rejected[0].Method, rejected[0].Endpoint)
	}
	for i, a := range audits {
		if a.Endpoint == "" {
			t.Errorf("audit[%d]: empty endpoint", i)
		}
		if a.Method != "POST" {
			t.Errorf("audit[%d]: method=%q, want POST", i, a.Method)
		}
	}
}

// TestToken_IPAllowlist_RejectsOtherIPs_AUDIT067 documents the IP
// allowlist status as of v0.10.363: NOT IMPLEMENTED — the per-probe
// source-IP allowlist is explicitly deferred in the AUDIT-067 spec.
//
// The current behavior is "any source IP that holds a valid token can
// authenticate". The CHANGELOG entry for v0.10.363 calls this out as
// follow-up work. This test pins the CURRENT contract so a future
// implementer doesn't quietly change the rejection behavior: the
// remote_ip field is recorded (for forensic review of an existing
// compromise) but is NOT a gate.
//
// When the deferred allowlist work lands, this test will be updated to
// seed an allowlist, set X-Forwarded-For/RemoteAddr to a non-allowlisted
// IP, and assert 403. That addition will be made in a follow-up PR.
func TestToken_IPAllowlist_RejectsOtherIPs_AUDIT067(t *testing.T) {
	h, db := setupTestHandler(t)
	const plainKey = "allowlist-test-probe-key"
	probe := seedProbe(t, db, "allowlist-probe", "tenant-Z", plainKey)

	// Two requests from "different" source IPs, both authenticated with
	// the same valid token. Pre-allowlist both should succeed; the audit
	// log records the source IP for each.
	get := func(remoteAddr string) *httptest.ResponseRecorder {
		router := gin.New()
		router.POST("/api/probes/:id/heartbeat", h.ProbeHeartbeat)
		body, _ := json.Marshal(map[string]interface{}{"probe_id": probe.ID, "status": "online"})
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/probes/%d/heartbeat", probe.ID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+plainKey)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if w := get("203.0.113.10:55555"); w.Code != http.StatusOK {
		t.Errorf("first-IP heartbeat: status=%d body=%s, want 200 (no allowlist gate yet — deferred)", w.Code, w.Body.String())
	}
	if w := get("198.51.100.42:55556"); w.Code != http.StatusOK {
		t.Errorf("second-IP heartbeat: status=%d body=%s, want 200 (no allowlist gate yet — deferred)", w.Code, w.Body.String())
	}

	// The audit log distinguishes the two source IPs — even without the
	// gate, an operator reviewing a compromise can pivot by IP. This is
	// the forensic-recording half of the eventual allowlist feature; it
	// stands on its own.
	var audits []models.ProbeTokenAudit
	if err := db.Gorm().Where("probe_id = ?", probe.ID).Order("id ASC").Find(&audits).Error; err != nil {
		t.Fatalf("load audits: %v", err)
	}
	if len(audits) != 2 {
		t.Fatalf("expected 2 audit rows, got %d", len(audits))
	}
	if audits[0].RemoteIP == "" || audits[1].RemoteIP == "" {
		t.Errorf("audit IPs not recorded: %q / %q", audits[0].RemoteIP, audits[1].RemoteIP)
	}
	if audits[0].RemoteIP == audits[1].RemoteIP {
		t.Errorf("audit IPs collapsed: both show %q (httptest should preserve RemoteAddr)", audits[0].RemoteIP)
	}
}
