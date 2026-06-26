package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

// fakeStore demonstrates the payoff of the repository-interface split: a handler
// can now be unit-tested with an in-memory fake instead of a real database.
// It embeds database.Store so it satisfies the full interface for free; only the
// methods a given test needs are overridden (any other call panics on the nil
// embedded interface, which is exactly what we want for a focused test).
type fakeStore struct {
	database.Store
	sites    []models.Site
	sitesErr error
}

// WithContextStore lets reqDB(c) work — it returns the same fake, ignoring the
// context (there's no real query to cancel).
func (f *fakeStore) WithContextStore(context.Context) database.Store { return f }

func (f *fakeStore) GetAllSites() ([]models.Site, error) { return f.sites, f.sitesErr }

func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin/api/sites", nil)
	return c, rec
}

// TestGetSites_WithFakeStore runs the real GetSites handler against a fake Store
// — no SQLite, no GORM, no migrations — proving handlers depend on the interface,
// not the concrete *database.Database.
func TestGetSites_WithFakeStore(t *testing.T) {
	want := []models.Site{{Name: "hq"}, {Name: "branch"}}
	h := &Handler{db: &fakeStore{sites: want}}

	c, rec := newTestContext()
	h.GetSites(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Data []models.Site `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) != 2 || resp.Data[0].Name != "hq" || resp.Data[1].Name != "branch" {
		t.Errorf("unexpected sites payload: %+v", resp.Data)
	}
}

// TestGetSites_FakeStoreError confirms the handler surfaces a store error as a
// 500 — again with no real database involved.
func TestGetSites_FakeStoreError(t *testing.T) {
	h := &Handler{db: &fakeStore{sitesErr: errors.New("boom")}}

	c, rec := newTestContext()
	h.GetSites(c)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
