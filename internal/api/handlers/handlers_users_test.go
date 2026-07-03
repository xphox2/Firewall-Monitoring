package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/config"
	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// userFakeStore overlays the UserStore methods on the shared fakeStore
// pattern (embedded database.Store; only what the tests touch is implemented).
type userFakeStore struct {
	fakeStore
	users       map[uint]*models.Admin
	otherAdmins int64
	deleted     []uint
	roleSet     map[uint]string
	disabledSet map[uint]bool
	pwReset     []uint
}

func newUserFakeStore() *userFakeStore {
	return &userFakeStore{
		users:       map[uint]*models.Admin{},
		roleSet:     map[uint]string{},
		disabledSet: map[uint]bool{},
	}
}

// WithContextStore must return the OUTER fake: the embedded fakeStore's
// version returns itself, which would strip these overrides and forward every
// call to the nil embedded Store (panic).
func (f *userFakeStore) WithContextStore(ctx context.Context) database.Store { return f }

func (f *userFakeStore) ListAdmins() ([]models.Admin, error) {
	var out []models.Admin
	for _, u := range f.users {
		out = append(out, *u)
	}
	return out, nil
}
func (f *userFakeStore) GetAdminByID(id uint) (*models.Admin, error) {
	u, ok := f.users[id]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}
func (f *userFakeStore) CreateAdmin(a *models.Admin) error {
	a.ID = uint(len(f.users) + 1)
	a.CreatedAt = time.Now()
	f.users[a.ID] = a
	return nil
}
func (f *userFakeStore) UpdateAdminRole(id uint, role string) error {
	f.roleSet[id] = role
	f.users[id].Role = role
	return nil
}
func (f *userFakeStore) SetAdminDisabled(id uint, disabled bool) error {
	f.disabledSet[id] = disabled
	f.users[id].Disabled = disabled
	return nil
}
func (f *userFakeStore) DeleteAdmin(id uint) error {
	f.deleted = append(f.deleted, id)
	delete(f.users, id)
	return nil
}
func (f *userFakeStore) CountOtherEnabledAdmins(excludeID uint) (int64, error) {
	return f.otherAdmins, nil
}
func (f *userFakeStore) UpdateAdminPassword(id uint, pw string) error { return nil }
func (f *userFakeStore) SetAdminMustChangePassword(id uint, m bool) error {
	f.pwReset = append(f.pwReset, id)
	return nil
}
func (f *userFakeStore) IncrementAdminTokenVersion(id uint) error { return nil }

func newUsersTestHandler(store *userFakeStore) *Handler {
	cfg := &config.Config{}
	cfg.Auth.BcryptCost = bcrypt.MinCost
	return &Handler{db: store, authManager: auth.NewAuthManager(cfg, nil)}
}

func usersCtx(method, path, body string, callerID uint) (*gin.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", callerID)
	c.Set("username", "caller")
	c.Set("role", auth.RoleAdmin)
	return c, rec
}

// TestCreateUser_ReturnsTempPasswordOnce: the response carries a temp password
// and the stored row holds only a bcrypt hash + the forced-change flag.
func TestCreateUser_ReturnsTempPasswordOnce(t *testing.T) {
	store := newUserFakeStore()
	h := newUsersTestHandler(store)

	c, rec := usersCtx(http.MethodPost, "/admin/api/users", `{"username":"newop","role":"operator"}`, 1)
	h.CreateUser(c)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			TempPassword string `json:"temp_password"`
			User         struct {
				MustChangePassword bool `json:"must_change_password"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.TempPassword == "" {
		t.Fatal("temp_password missing from create response")
	}
	if !resp.Data.User.MustChangePassword {
		t.Error("created user must be flagged must_change_password")
	}
	created := store.users[1]
	if created.Password == resp.Data.TempPassword {
		t.Error("plaintext temp password stored instead of hash")
	}
	if bcrypt.CompareHashAndPassword([]byte(created.Password), []byte(resp.Data.TempPassword)) != nil {
		t.Error("stored hash does not match the returned temp password")
	}
}

func TestCreateUser_RejectsBadRole(t *testing.T) {
	h := newUsersTestHandler(newUserFakeStore())
	c, rec := usersCtx(http.MethodPost, "/admin/api/users", `{"username":"x-user","role":"superuser"}`, 1)
	h.CreateUser(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestDeleteUser_Guards: self-delete is blocked, and deleting the last enabled
// admin is blocked.
func TestDeleteUser_Guards(t *testing.T) {
	store := newUserFakeStore()
	store.users[1] = &models.Admin{ID: 1, Username: "root", Role: auth.RoleAdmin}
	store.users[2] = &models.Admin{ID: 2, Username: "other", Role: auth.RoleAdmin}
	h := newUsersTestHandler(store)

	// Self-delete blocked.
	c, rec := usersCtx(http.MethodDelete, "/admin/api/users/1", "", 1)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	h.DeleteUser(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("self-delete: status = %d, want 400", rec.Code)
	}

	// Deleting the last OTHER enabled admin blocked (counter says none remain).
	store.otherAdmins = 0
	c, rec = usersCtx(http.MethodDelete, "/admin/api/users/2", "", 1)
	c.Params = gin.Params{{Key: "id", Value: "2"}}
	h.DeleteUser(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("last-admin delete: status = %d, want 400", rec.Code)
	}
	if len(store.deleted) != 0 {
		t.Errorf("no delete should have happened, got %v", store.deleted)
	}

	// With another admin present, the delete goes through.
	store.otherAdmins = 1
	c, rec = usersCtx(http.MethodDelete, "/admin/api/users/2", "", 1)
	c.Params = gin.Params{{Key: "id", Value: "2"}}
	h.DeleteUser(c)
	if rec.Code != http.StatusOK {
		t.Errorf("valid delete: status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestUpdateUser_Guards: no self-demotion, and the last enabled admin cannot
// be demoted or disabled.
func TestUpdateUser_Guards(t *testing.T) {
	store := newUserFakeStore()
	store.users[1] = &models.Admin{ID: 1, Username: "root", Role: auth.RoleAdmin}
	store.users[2] = &models.Admin{ID: 2, Username: "other", Role: auth.RoleAdmin}
	h := newUsersTestHandler(store)

	// Self-demotion blocked.
	c, rec := usersCtx(http.MethodPut, "/admin/api/users/1", `{"role":"viewer"}`, 1)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	h.UpdateUser(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("self-demote: status = %d, want 400", rec.Code)
	}

	// Demoting the last other admin blocked.
	store.otherAdmins = 0
	c, rec = usersCtx(http.MethodPut, "/admin/api/users/2", `{"role":"operator"}`, 1)
	c.Params = gin.Params{{Key: "id", Value: "2"}}
	h.UpdateUser(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("last-admin demote: status = %d, want 400", rec.Code)
	}

	// Disabling the last other admin blocked.
	c, rec = usersCtx(http.MethodPut, "/admin/api/users/2", `{"disabled":true}`, 1)
	c.Params = gin.Params{{Key: "id", Value: "2"}}
	h.UpdateUser(c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("last-admin disable: status = %d, want 400", rec.Code)
	}

	// With headroom, demote works and lands in the store.
	store.otherAdmins = 1
	c, rec = usersCtx(http.MethodPut, "/admin/api/users/2", `{"role":"operator"}`, 1)
	c.Params = gin.Params{{Key: "id", Value: "2"}}
	h.UpdateUser(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid demote: status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if store.roleSet[2] != auth.RoleOperator {
		t.Errorf("role not persisted: %q", store.roleSet[2])
	}
}
