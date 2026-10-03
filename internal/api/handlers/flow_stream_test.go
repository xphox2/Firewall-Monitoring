package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

	for _, q := range []string{"/x?hours=24", "/x?hours=24&src_addr=10.0.0.1", "/x?hours=6&dst_port=443"} {
		w = getRecorder(h.GetFlowStatsStream, q)
		evs = parseSSE(w.Body.String())
		if len(evs) == 0 || evs[len(evs)-1].name != "result" {
			t.Fatalf("%s was gated behind the long-report slots: %+v", q, evs)
		}
	}
}

// slowFlowStore stands in for a report with a long stretch and no event: its
// GetFlowStatsOpts returns only after `wait`.
type slowFlowStore struct {
	database.Store
	wait time.Duration
}

func (s *slowFlowStore) WithContextStore(context.Context) database.Store { return s }
func (s *slowFlowStore) GetFlowStatsOpts(int, database.FlowStatsFilter, database.FlowStatsOptions) (*database.FlowStatsResult, error) {
	time.Sleep(s.wait)
	return &database.FlowStatsResult{TotalFlows: 1}, nil
}
func (s *slowFlowStore) GetMixedFlowSourceDevices() []string { return nil }

// A report has no time limit, so a stretch with no event can outlast a
// reverse proxy's idle timeout (60 s by default). The stream must write a
// keepalive comment while nothing else is due.
func TestGetFlowStatsStream_KeepaliveDuringASilentStretch(t *testing.T) {
	h, _ := setupTestHandler(t)
	h.db = &slowFlowStore{wait: 250 * time.Millisecond}
	old := flowStreamKeepalive
	flowStreamKeepalive = 40 * time.Millisecond
	defer func() { flowStreamKeepalive = old }()

	w := getRecorder(h.GetFlowStatsStream, "/x?hours=24")
	body := w.Body.String()
	if n := strings.Count(body, ": keepalive\n\n"); n < 3 {
		t.Fatalf("%d keepalive comments during a 250 ms silent stretch at a 40 ms interval; body: %q", n, body)
	}
	evs := parseSSE(body)
	if len(evs) == 0 || evs[len(evs)-1].name != "result" {
		t.Fatalf("the stream must still end with its result: %+v", evs)
	}
}

// failingWriter is a recorder whose writes fail once `fail` is set — a client
// that has stopped reading, as net/http reports it to the handler.
type failingWriter struct {
	*httptest.ResponseRecorder
	fail atomic.Bool
}

func (w *failingWriter) Write(b []byte) (int, error) {
	if w.fail.Load() {
		return 0, errors.New("write: broken pipe")
	}
	return w.ResponseRecorder.Write(b)
}

// cancelAwareStore reports progress once and then waits for its context to
// be cancelled, or for `patience` to pass.
type cancelAwareStore struct {
	database.Store
	ctx       context.Context
	patience  time.Duration
	cancelled atomic.Bool
}

func (s *cancelAwareStore) WithContextStore(ctx context.Context) database.Store {
	s.ctx = ctx
	return s
}
func (s *cancelAwareStore) GetFlowStatsOpts(_ int, _ database.FlowStatsFilter, opts database.FlowStatsOptions) (*database.FlowStatsResult, error) {
	opts.Progress(database.FlowStatsProgress{Done: 1, Total: 2, Label: "x"})
	select {
	case <-s.ctx.Done():
		s.cancelled.Store(true)
		return nil, s.ctx.Err()
	case <-time.After(s.patience):
		return &database.FlowStatsResult{TotalFlows: 1}, nil
	}
}
func (s *cancelAwareStore) GetMixedFlowSourceDevices() []string { return nil }

// A client that stops reading must stop the report: the first failed write
// (a progress event here) cancels the context the report runs on, instead of
// the report running to completion on a dead connection.
func TestGetFlowStatsStream_FailedWriteCancelsTheReport(t *testing.T) {
	h, _ := setupTestHandler(t)
	store := &cancelAwareStore{patience: 3 * time.Second}
	h.db = store

	w := &failingWriter{ResponseRecorder: httptest.NewRecorder()}
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x?hours=24", nil)
	w.fail.Store(true) // every event write fails, headers already went out
	start := time.Now()
	h.GetFlowStatsStream(c)
	if !store.cancelled.Load() {
		t.Fatalf("the report's context was not cancelled after a failed write (handler took %s)", time.Since(start))
	}
}

// The same through the keepalive: no event is due, the keepalive write fails,
// the report is cancelled.
func TestGetFlowStatsStream_FailedKeepaliveCancelsTheReport(t *testing.T) {
	h, _ := setupTestHandler(t)
	store := &cancelAwareStore{patience: 3 * time.Second}
	h.db = store
	old := flowStreamKeepalive
	flowStreamKeepalive = 20 * time.Millisecond
	defer func() { flowStreamKeepalive = old }()

	w := &failingWriter{ResponseRecorder: httptest.NewRecorder()}
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x?hours=24", nil)
	go func() {
		time.Sleep(50 * time.Millisecond) // after the progress event, before a keepalive
		w.fail.Store(true)
	}()
	h.GetFlowStatsStream(c)
	if !store.cancelled.Load() {
		t.Fatal("the report's context was not cancelled after a failed keepalive write")
	}
}

// hoursStore records the window the stream asked for.
type hoursStore struct {
	database.Store
	hours int
}

func (s *hoursStore) WithContextStore(context.Context) database.Store { return s }
func (s *hoursStore) GetFlowStatsOpts(hours int, _ database.FlowStatsFilter, _ database.FlowStatsOptions) (*database.FlowStatsResult, error) {
	s.hours = hours
	return &database.FlowStatsResult{}, nil
}
func (s *hoursStore) GetMixedFlowSourceDevices() []string { return nil }

// The streamed report has no time limit and holds one of two slots, so its
// window is capped at the page's largest preset (90 days); the synchronous
// endpoint keeps ParseHours' year.
func TestGetFlowStatsStream_WindowCappedAtLargestPreset(t *testing.T) {
	h, _ := setupTestHandler(t)
	store := &hoursStore{}
	h.db = store
	getRecorder(h.GetFlowStatsStream, "/x?hours=8760")
	if store.hours != flowStreamMaxHours {
		t.Fatalf("stream ran hours=%d, want %d", store.hours, flowStreamMaxHours)
	}
	getRecorder(h.GetFlowStatsStream, "/x?hours=720")
	if store.hours != 720 {
		t.Fatalf("stream ran hours=%d, want 720 (under the cap, unchanged)", store.hours)
	}
	getRecorder(h.GetFlowStats, "/x?hours=8760")
	if store.hours != 8760 {
		t.Fatalf("the synchronous endpoint ran hours=%d, want 8760 (not capped)", store.hours)
	}
}
