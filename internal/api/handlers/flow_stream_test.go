package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

type sseEvent struct {
	name string
	data string
}

func parseSSE(body string) []sseEvent {
	var out []sseEvent
	for _, block := range strings.Split(body, "\n\n") {
		var ev sseEvent
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			}
		}
		if ev.name != "" {
			out = append(out, ev)
		}
	}
	return out
}

func seedFlowStreamRollups(t *testing.T, db *database.Database) {
	t.Helper()
	now := time.Now()
	var rows []models.FlowRollup
	for day := 0; day < 5; day++ {
		rows = append(rows, models.FlowRollup{
			Timestamp: now.Add(-time.Duration(day*24+12) * time.Hour), DeviceID: 1, IntervalType: "1h",
			SrcAddr: "10.0.0.1", DstAddr: "8.8.8.8", DstPort: 443, Protocol: 6,
			BytesSum: uint64(1000 * (day + 1)), PacketsSum: 3, FlowCount: 2, SamplingRateAvg: 1,
		})
	}
	if err := db.Gorm().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
}

func getRecorder(h gin.HandlerFunc, url string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	h(c)
	return w
}

// The stream's result must be exactly what /flows/stats returns for the same
// query, preceded by progress, and the stream must end right after it.
func TestGetFlowStatsStream_ResultMatchesSyncEndpoint(t *testing.T) {
	h, db := setupTestHandler(t)
	seedFlowStreamRollups(t, db)
	const q = "/x?hours=168&src_addr=10.0.0.1"

	sync := getRecorder(h.GetFlowStats, q)
	var syncBody struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(sync.Body.Bytes(), &syncBody); err != nil {
		t.Fatal(err)
	}

	w := getRecorder(h.GetFlowStatsStream, q)
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	evs := parseSSE(w.Body.String())
	if len(evs) < 3 || evs[0].name != "progress" {
		t.Fatalf("events %+v, want progress first", evs)
	}
	last := evs[len(evs)-1]
	if last.name != "result" {
		t.Fatalf("last event %q, want result and nothing after it", last.name)
	}
	var got struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(last.data), &got); err != nil || !got.Success {
		t.Fatalf("result %s: %v", last.data, err)
	}
	if string(got.Data) != string(syncBody.Data) {
		t.Fatalf("stream result differs from /flows/stats:\nstream: %s\nsync:   %s", got.Data, syncBody.Data)
	}
	if !strings.Contains(w.Body.String(), "Reading day 1 of 7") {
		t.Fatal("no per-day progress for a materialized report")
	}
}

// Only long reports take a slot: with both slots held, a filtered long report
// is refused with a 200 `fail` event (never a status code, so the page never
// mistakes it for a transport failure), while the default view is not gated.
func TestGetFlowStatsStream_SlotsGateOnlyLongReports(t *testing.T) {
	h, db := setupTestHandler(t)
	seedFlowStreamRollups(t, db)
	for i := 0; i < cap(flowStreamSlots); i++ {
		flowStreamSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(flowStreamSlots); i++ {
			<-flowStreamSlots
		}
	}()

	w := getRecorder(h.GetFlowStatsStream, "/x?hours=168&src_addr=10.0.0.1")
	evs := parseSSE(w.Body.String())
	if w.Code != http.StatusOK || len(evs) != 1 || evs[0].name != "fail" || !strings.Contains(evs[0].data, "Another long Flows report") {
		t.Fatalf("busy reply: code %d events %+v", w.Code, evs)
	}

	w = getRecorder(h.GetFlowStatsStream, "/x?hours=24")
	evs = parseSSE(w.Body.String())
	if len(evs) == 0 || evs[len(evs)-1].name != "result" {
		t.Fatalf("the default view was gated: %+v", evs)
	}
}
