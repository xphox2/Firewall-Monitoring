package handlers

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// statEntry mirrors one element of GetProbesStatsBatch's response array.
type statEntry struct {
	ProbeID  uint  `json:"probe_id"`
	Syslog   int64 `json:"syslog"`
	Traps    int64 `json:"traps"`
	Flows    int64 `json:"flows"`
	Pings    int64 `json:"pings"`
	LastHour struct {
		Syslog int64 `json:"syslog"`
		Traps  int64 `json:"traps"`
		Flows  int64 `json:"flows"`
		Pings  int64 `json:"pings"`
	} `json:"last_hour"`
}

// TestGetProbesStatsBatch_AUDIT064 verifies the batch stats endpoint returns
// correct total + last-hour counts per probe in a single request, replacing
// the N+1 the probes summary page used to make (one /probes/:id/stats per
// probe). It also confirms the last-hour window and that an unrequested probe
// is not included.
func TestGetProbesStatsBatch_AUDIT064(t *testing.T) {
	h, db := setupTestHandler(t)

	p1 := &models.Probe{Name: "p1", RegistrationKey: "k1", ApprovalStatus: "approved", Status: "online"}
	p2 := &models.Probe{Name: "p2", RegistrationKey: "k2", ApprovalStatus: "approved", Status: "online"}
	p3 := &models.Probe{Name: "p3", RegistrationKey: "k3", ApprovalStatus: "approved", Status: "online"}
	for _, p := range []*models.Probe{p1, p2, p3} {
		if err := db.Gorm().Create(p).Error; err != nil {
			t.Fatalf("create probe %s: %v", p.Name, err)
		}
	}

	now := time.Now().UTC()
	recent := now.Add(-10 * time.Minute)
	old := now.Add(-3 * time.Hour)
	mk := func(rec interface{}) {
		if err := db.Gorm().Create(rec).Error; err != nil {
			t.Fatalf("create %T: %v", rec, err)
		}
	}

	// p1: syslog 3 (2 recent), traps 2 (1 recent), flows 1 (recent), pings 1 (old)
	mk(&models.SyslogMessage{ProbeID: p1.ID, Timestamp: recent})
	mk(&models.SyslogMessage{ProbeID: p1.ID, Timestamp: recent})
	mk(&models.SyslogMessage{ProbeID: p1.ID, Timestamp: old})
	mk(&models.TrapEvent{ProbeID: p1.ID, Timestamp: recent})
	mk(&models.TrapEvent{ProbeID: p1.ID, Timestamp: old})
	mk(&models.FlowSample{ProbeID: p1.ID, Timestamp: recent})
	mk(&models.PingResult{ProbeID: p1.ID, Timestamp: old})
	// p2: syslog 1 (recent)
	mk(&models.SyslogMessage{ProbeID: p2.ID, Timestamp: recent})
	// p3: data exists but p3 is NOT requested — must not appear.
	mk(&models.SyslogMessage{ProbeID: p3.ID, Timestamp: recent})

	router := gin.New()
	router.GET("/probes/stats", h.GetProbesStatsBatch)
	req := httptest.NewRequest("GET", fmt.Sprintf("/probes/stats?ids=%d,%d", p1.ID, p2.ID), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Success bool        `json:"success"`
		Data    []statEntry `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, w.Body.String())
	}
	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 entries (p3 not requested), got %d: %s", len(resp.Data), w.Body.String())
	}

	byID := map[uint]statEntry{}
	for _, d := range resp.Data {
		byID[d.ProbeID] = d
	}

	s1 := byID[p1.ID]
	if s1.Syslog != 3 || s1.LastHour.Syslog != 2 {
		t.Errorf("p1 syslog total/hr = %d/%d, want 3/2", s1.Syslog, s1.LastHour.Syslog)
	}
	if s1.Traps != 2 || s1.LastHour.Traps != 1 {
		t.Errorf("p1 traps total/hr = %d/%d, want 2/1", s1.Traps, s1.LastHour.Traps)
	}
	if s1.Flows != 1 || s1.LastHour.Flows != 1 {
		t.Errorf("p1 flows total/hr = %d/%d, want 1/1", s1.Flows, s1.LastHour.Flows)
	}
	if s1.Pings != 1 || s1.LastHour.Pings != 0 {
		t.Errorf("p1 pings total/hr = %d/%d, want 1/0", s1.Pings, s1.LastHour.Pings)
	}

	s2 := byID[p2.ID]
	if s2.Syslog != 1 || s2.LastHour.Syslog != 1 {
		t.Errorf("p2 syslog total/hr = %d/%d, want 1/1", s2.Syslog, s2.LastHour.Syslog)
	}
	if s2.Traps != 0 || s2.Flows != 0 || s2.Pings != 0 {
		t.Errorf("p2 non-syslog totals = traps %d flows %d pings %d, want 0/0/0", s2.Traps, s2.Flows, s2.Pings)
	}

	if _, ok := byID[p3.ID]; ok {
		t.Errorf("p3 was not requested but appeared in the batch response")
	}
}

// TestGetProbesStatsBatch_EmptyIDs_AUDIT064 verifies the no-ids path returns an
// empty array, not an error.
func TestGetProbesStatsBatch_EmptyIDs_AUDIT064(t *testing.T) {
	h, _ := setupTestHandler(t)
	router := gin.New()
	router.GET("/probes/stats", h.GetProbesStatsBatch)

	for _, q := range []string{"", "?ids=", "?ids=,,"} {
		req := httptest.NewRequest("GET", "/probes/stats"+q, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("ids=%q: status %d: %s", q, w.Code, w.Body.String())
		}
		var resp struct {
			Data []statEntry `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("ids=%q: unmarshal: %v", q, err)
		}
		if len(resp.Data) != 0 {
			t.Errorf("ids=%q: expected empty data, got %d entries", q, len(resp.Data))
		}
	}
}
