package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"firewall-mon/internal/alerts"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"
	"firewall-mon/internal/notifier"

	"github.com/gin-gonic/gin"
)

// setupTestHandlerWithAlerts wires a real AlertManager (backed by the same test
// DB) so RecordProbeDataTruncation actually writes a PROBE_DATA_TRUNCATED alert
// row we can assert on — the truncation SIGNAL that AUDIT-196's streaming decode
// must preserve.
func setupTestHandlerWithAlerts(t *testing.T) (*Handler, *database.Database) {
	t.Helper()
	h, db := setupTestHandler(t)
	cfg := &config.Config{}
	am := alerts.NewAlertManager(cfg, notifier.NewNotifier(cfg), db)
	h.SetAlertManager(am)
	return h, db
}

func savedCount(t *testing.T, body []byte) float64 {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v (%s)", err, string(body))
	}
	data, _ := resp["data"].(map[string]interface{})
	saved, _ := data["saved"].(float64)
	return saved
}

func truncationAlertCount(t *testing.T, db *database.Database) int64 {
	t.Helper()
	var n int64
	if err := db.Gorm().Model(&models.Alert{}).
		Where("alert_type = ?", "PROBE_DATA_TRUNCATED").Count(&n).Error; err != nil {
		t.Fatalf("count truncation alerts: %v", err)
	}
	return n
}

// ── AUDIT-196: decode-time cap + preserved truncation alert ───────────────────

// TestReceiveSystemStatuses_TruncationAlertFires pins the AUDIT-196 requirement
// that the decode caps at 100 AND the operator-visible PROBE_DATA_TRUNCATED
// alert still fires (the streaming decoder counts the dropped tail without
// retaining it, so the 20%-overshoot threshold is evaluated on the true count).
func TestReceiveSystemStatuses_TruncationAlertFires(t *testing.T) {
	h, db := setupTestHandlerWithAlerts(t)
	probe, device := setupProbeAndDevice(t, db)

	statuses := make([]map[string]interface{}, 200) // cap 100, >20% overshoot
	for i := range statuses {
		statuses[i] = map[string]interface{}{
			"device_id": device.ID,
			"probe_id":  probe.ID,
			"timestamp": time.Now(),
		}
	}

	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey, statuses)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 100 {
		t.Errorf("saved = %v, want exactly 100 (decode cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 1 {
		t.Errorf("PROBE_DATA_TRUNCATED alerts = %d, want 1 (truncation signal lost)", got)
	}
}

// TestReceiveFlowSamples_CapsAt1000AndAlerts is the flows (cap 1000) counterpart:
// a 1300-sample batch is capped to 1000 and fires exactly one truncation alert.
func TestReceiveFlowSamples_CapsAt1000AndAlerts(t *testing.T) {
	h, db := setupTestHandlerWithAlerts(t)
	probe, _ := setupProbeAndDevice(t, db)

	samples := make([]map[string]interface{}, 1300)
	for i := range samples {
		// DeviceID 0 / no sampler address → passes the ownership filter unchanged,
		// so `saved` reflects the decode cap, not device filtering.
		samples[i] = map[string]interface{}{"timestamp": time.Now()}
	}

	w := doTestRequest(t, h.ReceiveFlowSamples, "POST", "/flow-samples", probe.ID, probe.RegistrationKey, samples)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 1000 {
		t.Errorf("saved = %v, want exactly 1000 (decode cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 1 {
		t.Errorf("PROBE_DATA_TRUNCATED alerts = %d, want 1", got)
	}
}

// TestReceiveSystemStatuses_NonArrayBody_Returns400 pins the malformed/non-array
// 400 shape the handlers' ShouldBindJSON path emitted (an object where an array
// is expected).
func TestReceiveSystemStatuses_NonArrayBody_Returns400(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, _ := setupProbeAndDevice(t, db)

	// A JSON object where the handler expects an array — pre-fix ShouldBindJSON
	// and post-fix decodeCappedArray both 400 this.
	w := doTestRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses", probe.ID, probe.RegistrationKey,
		map[string]interface{}{"not": "an array"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("non-array body: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

// ── AUDIT-253: the eleven [:500] endpoints now cap at 1000, not 500 ───────────

// TestReceiveVPNStatuses_KeepsRowsBeyond500 is the load-bearing pre-fix-failing
// test: the old handler silently resliced to [:500], dropping rows 501+ with no
// alert. Post-fix the cap is 1000, so a 700-row batch of owned devices keeps ALL
// 700 (pre-fix: 500), and only past 1000 does truncation kick in (with the alert
// AUDIT-196 preserved — pre-fix the [:500] path emitted none).
func TestReceiveVPNStatuses_KeepsRowsBeyond500(t *testing.T) {
	h, db := setupTestHandlerWithAlerts(t)
	probe, device := setupProbeAndDevice(t, db)

	mk := func(n int) []map[string]interface{} {
		rows := make([]map[string]interface{}, n)
		for i := range rows {
			rows[i] = map[string]interface{}{
				"device_id": device.ID,
				"probe_id":  probe.ID,
				"timestamp": time.Now(),
			}
		}
		return rows
	}

	// 700 > old 500 cap: every row must survive now.
	w := doTestRequest(t, h.ReceiveVPNStatuses, "POST", "/vpn-statuses", probe.ID, probe.RegistrationKey, mk(700))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 700 {
		t.Errorf("saved = %v, want 700 (rows 501-700 were dropped at the old 500 cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 0 {
		t.Errorf("truncation alerts = %d, want 0 (700 <= 1000 cap, no truncation)", got)
	}

	// 1300 > 1000 cap: truncated to 1000 and the alert fires.
	w = doTestRequest(t, h.ReceiveVPNStatuses, "POST", "/vpn-statuses", probe.ID, probe.RegistrationKey, mk(1300))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if saved := savedCount(t, w.Body.Bytes()); saved != 1000 {
		t.Errorf("saved = %v, want 1000 (cap)", saved)
	}
	if got := truncationAlertCount(t, db); got != 1 {
		t.Errorf("truncation alerts = %d, want 1 (1300 > 1000 must alert)", got)
	}
}

// ── AUDIT-255: empty post-filter slice must be 200 {saved:0}, not 500 ─────────

// TestReceiveTailHandlers_AllNotOwned_Returns200 covers the three gorm.Create
// endpoints (InterfaceErrors, SensorDetails, LicenseDetails). Pre-fix, a batch of
// only not-owned devices filtered to an empty slice and gorm.Create returned
// ErrEmptySlice → 500. Post-fix each guards len==0 and returns 200 {saved:0}.
func TestReceiveTailHandlers_AllNotOwned_Returns200(t *testing.T) {
	cases := []struct {
		name string
		path string
		pick func(*Handler) func(*gin.Context)
	}{
		{"InterfaceErrors", "/interface-errors", func(h *Handler) func(*gin.Context) { return h.ReceiveInterfaceErrors }},
		{"SensorDetails", "/sensor-details", func(h *Handler) func(*gin.Context) { return h.ReceiveSensorDetails }},
		{"LicenseDetails", "/license-details", func(h *Handler) func(*gin.Context) { return h.ReceiveLicenseDetails }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db := setupTestHandler(t)
			probe, _ := setupProbeAndDevice(t, db)
			other := &models.Device{Name: "other-fw", IPAddress: "10.77.0.9"}
			if err := db.Gorm().Create(other).Error; err != nil {
				t.Fatalf("create other device: %v", err)
			}
			body := []map[string]interface{}{{
				"device_id": other.ID,
				"probe_id":  probe.ID,
				"timestamp": time.Now(),
			}}
			w := doTestRequest(t, tc.pick(h), "POST", tc.path, probe.ID, probe.RegistrationKey, body)
			if w.Code != http.StatusOK {
				t.Fatalf("%s all-not-owned: status = %d, want 200 (empty filter must not 500); body: %s", tc.name, w.Code, w.Body.String())
			}
			if saved := savedCount(t, w.Body.Bytes()); saved != 0 {
				t.Errorf("%s: saved = %v, want 0", tc.name, saved)
			}
		})
	}
}

// ── AUDIT-254: the config-revision row lock is a real GORM-v2 clause ──────────

// TestReceiveConfigRevision_UsesRowLockClause is a source-level guard: the
// GORM-v1 `gorm:query_option` "FOR UPDATE" key was silently ignored by GORM v2
// (no lock → concurrent backups for one device both read the same prevRev, both
// INSERT → duplicate revisions + CONFIG_CHANGE alerts). The fix must use the v2
// clause.Locking clause and the dead v1 key must be gone. SQLite serializes the
// whole DB so a true concurrency test can't distinguish them; this guards the
// mechanism that protects Postgres.
func TestReceiveConfigRevision_UsesRowLockClause(t *testing.T) {
	src, err := os.ReadFile("handlers_data.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	s := string(src)
	if strings.Contains(s, `gorm:query_option`) {
		t.Error("handlers_data.go still uses the GORM-v1 `gorm:query_option` key (a v2 no-op)")
	}
	if !strings.Contains(s, `clause.Locking{Strength: "UPDATE"}`) {
		t.Error("handlers_data.go must lock with clause.Locking{Strength: \"UPDATE\"} (real FOR UPDATE)")
	}
}

// ── AUDIT-196 follow-up: a truncated body must 400 and NOT dedup-mark ─────────

// doRawProbeRequest posts a RAW (unmarshaled) body with arbitrary headers to a
// probe handler — used to send a deliberately malformed/truncated JSON body that
// json.Marshal could never produce.
func doRawProbeRequest(t *testing.T, h func(*gin.Context), method, path string, probeID uint, authKey, rawBody string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.Handle(method, "/probes/:id"+path, h)

	req := httptest.NewRequest(method, fmt.Sprintf("/probes/%d%s", probeID, path), strings.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	if authKey != "" {
		req.Header.Set("Authorization", "Bearer "+authKey)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestReceiveSystemStatuses_TruncatedBody_400AndNotDeduped is the reviewer's HIGH
// regression: a body cut mid-array (`[{...},{...}` with no closing `]`) must 400
// and MUST NOT mark the idempotency batch id processed — otherwise the
// collector's retry would be deduped and the tail lost forever with no alert.
// json.Decoder.More() swallows the read error, so pre-fix this returned a partial
// 200 and marked the batch. Fails pre-this-fix.
func TestReceiveSystemStatuses_TruncatedBody_400AndNotDeduped(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)

	const batchID = "batch-truncated-1"
	rawBody := fmt.Sprintf(`[{"device_id":%d},{"device_id":%d}`, device.ID, device.ID) // no closing ]

	w := doRawProbeRequest(t, h.ReceiveSystemStatuses, "POST", "/system-statuses",
		probe.ID, probe.RegistrationKey, rawBody, map[string]string{"X-Probe-Batch-ID": batchID})

	if w.Code != http.StatusBadRequest {
		t.Errorf("truncated body: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if db.BatchAlreadyProcessed(probe.ID, batchID) {
		t.Error("truncated body marked the batch id processed — the collector's retry will be deduped and the tail lost")
	}
	var count int64
	db.Gorm().Model(&models.SystemStatus{}).Where("device_id = ?", device.ID).Count(&count)
	if count != 0 {
		t.Errorf("truncated body saved %d partial rows, want 0", count)
	}
}

// ── AUDIT-196: decoder-level memory + shape unit tests ────────────────────────

// countingElem counts every time the JSON decoder MATERIALIZES an element into a
// struct — the only way to pin decodeCappedArray's memory claim (at most capN
// elements are ever decoded; the tail is drained as raw bytes).
type countingElem struct {
	DeviceID uint `json:"device_id"`
}

var decodeMaterializeCount int32

func (e *countingElem) UnmarshalJSON(b []byte) error {
	atomic.AddInt32(&decodeMaterializeCount, 1)
	return nil
}

func newDecodeCtx(body string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/", strings.NewReader(body))
	return c, w
}

// TestDecodeCappedArray_MaterializesAtMostCapN pins the AUDIT-196 memory
// guarantee: for an over-cap array only capN elements are ever decoded into
// structs, while `total` still reflects the true element count for the alert.
func TestDecodeCappedArray_MaterializesAtMostCapN(t *testing.T) {
	var sb strings.Builder
	sb.WriteByte('[')
	const n = 250
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"device_id":1}`)
	}
	sb.WriteByte(']')

	atomic.StoreInt32(&decodeMaterializeCount, 0)
	c, _ := newDecodeCtx(sb.String())

	out, total, ok := decodeCappedArray[countingElem](c, 100)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(out) != 100 {
		t.Errorf("len(out) = %d, want 100", len(out))
	}
	if total != n {
		t.Errorf("total = %d, want %d (exact count for the truncation alert)", total, n)
	}
	if got := atomic.LoadInt32(&decodeMaterializeCount); got != 100 {
		t.Errorf("materialized %d elements, want exactly 100 — memory cap breached (the whole array was decoded)", got)
	}
}

// TestDecodeCappedArray_NullBody_EmptyBatch: a bare JSON null decodes as an empty
// batch (ok=true, total=0), matching ShouldBindJSON(&slice) → nil slice.
func TestDecodeCappedArray_NullBody_EmptyBatch(t *testing.T) {
	c, _ := newDecodeCtx("null")
	out, total, ok := decodeCappedArray[countingElem](c, 100)
	if !ok || total != 0 || len(out) != 0 {
		t.Errorf("null body: out=%v total=%d ok=%v, want empty ok batch", out, total, ok)
	}
}

// TestDecodeCappedArray_MalformedDrainTail_400: a malformed element in the drained
// (over-cap) tail is a bad body and must 400, matching pre-fix full-decode reject.
func TestDecodeCappedArray_MalformedDrainTail_400(t *testing.T) {
	c, w := newDecodeCtx(`[{"device_id":1},{"device_id":1},{"device_id":1},garbage]`)
	_, _, ok := decodeCappedArray[countingElem](c, 2)
	if ok {
		t.Error("malformed drain tail: ok = true, want false")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed drain tail: status = %d, want 400", w.Code)
	}
}

// TestDecodeCappedArray_TruncatedNoCloser_400: a well-formed prefix with no
// closing `]` must 400 (the closing-delimiter check), even though json.More()
// swallowed the underlying EOF.
func TestDecodeCappedArray_TruncatedNoCloser_400(t *testing.T) {
	c, w := newDecodeCtx(`[{"device_id":1},{"device_id":1}`)
	_, _, ok := decodeCappedArray[countingElem](c, 100)
	if ok {
		t.Error("truncated no-closer: ok = true, want false")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("truncated no-closer: status = %d, want 400", w.Code)
	}
}

// TestDecodeCappedArray_HappyShapes: normal array, [], and trailing garbage after
// `]` (unread, lenient — matches ShouldBindJSON) all decode ok.
func TestDecodeCappedArray_HappyShapes(t *testing.T) {
	c, _ := newDecodeCtx(`[{"device_id":1},{"device_id":2}]`)
	out, total, ok := decodeCappedArray[countingElem](c, 100)
	if !ok || len(out) != 2 || total != 2 {
		t.Errorf("normal array: out=%d total=%d ok=%v, want 2/2/true", len(out), total, ok)
	}

	c, _ = newDecodeCtx(`[]`)
	out, total, ok = decodeCappedArray[countingElem](c, 100)
	if !ok || len(out) != 0 || total != 0 {
		t.Errorf("empty array: out=%d total=%d ok=%v, want 0/0/true", len(out), total, ok)
	}

	c, _ = newDecodeCtx(`[{"device_id":1}]trailing garbage`)
	out, total, ok = decodeCappedArray[countingElem](c, 100)
	if !ok || len(out) != 1 || total != 1 {
		t.Errorf("trailing garbage: out=%d total=%d ok=%v, want 1/1/true", len(out), total, ok)
	}
}
