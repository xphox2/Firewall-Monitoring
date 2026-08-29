package auth

// White-box (package auth) on purpose: the AUDIT-262 fix is pinned
// structurally — dummyHash is built lazily, exactly once, and the burn happens
// on both bcrypt-skipping paths — rather than with a flaky wall-clock timing
// assertion. The black-box behavior tests live in auth_test.go (package
// auth_test).

import (
	"testing"
	"time"

	"firewall-mon/internal/config"

	"golang.org/x/crypto/bcrypt"
)

// missDB is an auth.Database whose GetAdminByUsername always misses — the
// unknown-username path.
type missDB struct{}

func (missDB) GetAdminByUsername(string) (*AdminAuth, error) { return nil, nil }
func (missDB) UpdateAdminPassword(uint, string) error        { return nil }
func (missDB) GetAdminTokenVersion(uint) (uint, error)       { return 0, nil }
func (missDB) IncrementAdminTokenVersion(uint) error         { return nil }

// emptyHashDB returns a real admin row whose stored password hash is empty —
// the second bcrypt-skipping early return.
type emptyHashDB struct{ missDB }

func (emptyHashDB) GetAdminByUsername(u string) (*AdminAuth, error) {
	return &AdminAuth{ID: 1, Username: u, Password: ""}, nil
}

func timingTestConfig() *config.Config {
	cfg := &config.Config{}
	// MinCost keeps the burned compare cheap in tests; compareDummy builds its
	// hash at the CONFIGURED cost for exactly this reason.
	cfg.Auth.BcryptCost = bcrypt.MinCost
	cfg.Auth.MaxLoginAttempts = 5
	cfg.Auth.LockoutDuration = 15 * time.Minute
	return cfg
}

// TestValidateCredentials_UnknownUserBurnsDummyBcrypt_AUDIT262: an unknown
// username must cost a full bcrypt comparison, or response latency becomes a
// remote username-enumeration oracle. Structural assertion: the dummy hash is
// built lazily by the miss path and, via sync.Once, exactly once.
func TestValidateCredentials_UnknownUserBurnsDummyBcrypt_AUDIT262(t *testing.T) {
	am := NewAuthManager(timingTestConfig(), missDB{})
	if am.dummyHash != nil {
		t.Fatal("dummyHash must be built lazily, not at construction")
	}

	if err := am.ValidateCredentials("ghost", "whatever", "1.2.3.4"); err != ErrInvalidCredentials {
		t.Fatalf("unknown user: got %v, want ErrInvalidCredentials", err)
	}
	if am.dummyHash == nil {
		t.Fatal("unknown-username path skipped the dummy bcrypt burn — the AUDIT-262 timing oracle is back")
	}
	if err := bcrypt.CompareHashAndPassword(am.dummyHash, []byte("firewall-mon-timing-uniformity-sentinel")); err != nil {
		t.Errorf("dummyHash is not a valid bcrypt hash of the sentinel: %v", err)
	}

	first := am.dummyHash
	if err := am.ValidateCredentials("ghost", "again", "1.2.3.4"); err != ErrInvalidCredentials {
		t.Fatalf("second unknown-user attempt: got %v, want ErrInvalidCredentials", err)
	}
	if &am.dummyHash[0] != &first[0] {
		t.Error("dummyHash was rebuilt on a second attempt — sync.Once must build it exactly once")
	}
}

// TestValidateCredentials_EmptyStoredHashBurnsDummyBcrypt_AUDIT262 pins the
// SECOND bcrypt-skipping early return the audit text did not name: a known
// user with an empty stored hash.
func TestValidateCredentials_EmptyStoredHashBurnsDummyBcrypt_AUDIT262(t *testing.T) {
	am := NewAuthManager(timingTestConfig(), emptyHashDB{})

	if err := am.ValidateCredentials("hollow", "whatever", "1.2.3.4"); err != ErrInvalidCredentials {
		t.Fatalf("empty stored hash: got %v, want ErrInvalidCredentials", err)
	}
	if am.dummyHash == nil {
		t.Fatal("empty-stored-hash path skipped the dummy bcrypt burn (AUDIT-262)")
	}
}
