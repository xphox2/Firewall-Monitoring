package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/time/rate"
)

// Ceremony kinds. A ceremony is only ever consumed as the kind it was stored
// as; presenting it as the other kind fails (and still consumes it).
const (
	KindLogin    = "login"
	KindRegister = "register"
)

// DefaultCeremonyCap bounds the in-memory store: unauthenticated login
// `begin` calls can never grow it past this many entries (the oldest entry is
// evicted to make room).
const DefaultCeremonyCap = 1000

// Ceremony is one in-flight WebAuthn ceremony.
type Ceremony struct {
	Kind    string
	AdminID uint   // registration: the session's account; 0 for login
	Name    string // registration: the requested passkey name
	Session webauthn.SessionData
}

type ceremonyEntry struct {
	c       Ceremony
	created time.Time
}

// CeremonyStore keeps ceremony state in API memory (the API is a singleton,
// AUDIT-040). Mutex-guarded, entries expire after ttl (checked lazily on
// every access), at most cap entries (oldest evicted), and Take deletes the
// entry under the lock before returning it — so a ceremony is strictly
// single-use, even under concurrent finishes. An API restart simply drops
// every ceremony ("try again").
type CeremonyStore struct {
	mu  sync.Mutex
	m   map[string]ceremonyEntry
	ttl time.Duration
	cap int
	now func() time.Time
}

// NewCeremonyStore returns an empty store.
func NewCeremonyStore(ttl time.Duration, capacity int) *CeremonyStore {
	if capacity < 1 {
		capacity = 1
	}
	return &CeremonyStore{m: map[string]ceremonyEntry{}, ttl: ttl, cap: capacity, now: time.Now}
}

// SetClockForTesting replaces the store's clock.
func (s *CeremonyStore) SetClockForTesting(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// sweepLocked drops expired entries. Caller holds mu.
func (s *CeremonyStore) sweepLocked(now time.Time) {
	for k, e := range s.m {
		if now.Sub(e.created) >= s.ttl {
			delete(s.m, k)
		}
	}
}

// Put stores c under key, replacing any existing entry with that key (a new
// registration begin supersedes the previous one for the same account).
func (s *CeremonyStore) Put(key string, c Ceremony) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked(now)
	delete(s.m, key)
	for len(s.m) >= s.cap {
		oldestKey, oldest := "", time.Time{}
		for k, e := range s.m {
			if oldestKey == "" || e.created.Before(oldest) {
				oldestKey, oldest = k, e.created
			}
		}
		delete(s.m, oldestKey)
	}
	s.m[key] = ceremonyEntry{c: c, created: now}
}

// Take consumes the entry stored under key. It returns the ceremony only if
// it exists, has not expired and was stored as kind; in every case the entry
// is gone afterwards (single use).
func (s *CeremonyStore) Take(kind, key string) (Ceremony, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.m[key]
	delete(s.m, key)
	s.sweepLocked(now)
	if !ok || now.Sub(e.created) >= s.ttl || e.c.Kind != kind {
		return Ceremony{}, false
	}
	return e.c, true
}

// Len reports the number of live entries (tests, diagnostics).
func (s *CeremonyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	return len(s.m)
}

// NewLoginCeremonyID returns a fresh random ceremony id: 32 bytes from
// crypto/rand, base64url-encoded (no padding) for the webauthn_login cookie.
func NewLoginCeremonyID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// RegistrationKey is the store key of an account's registration ceremony (at
// most one outstanding per account). It contains ':' so it can never collide
// with a base64url login ceremony id.
func RegistrationKey(adminID uint) string {
	return "register:" + strconv.FormatUint(uint64(adminID), 10)
}

// ReauthLimiter is the dedicated per-user limiter for the passkey
// re-authentication endpoints (register-begin, delete): a burst of 5, then one
// attempt per minute. It counts every attempt, successful or not, and is
// separate from the login lockout (a wrong password here never locks the
// account's login).
type ReauthLimiter struct {
	mu sync.Mutex
	m  map[uint]*rate.Limiter
}

// NewReauthLimiter returns an empty limiter set.
func NewReauthLimiter() *ReauthLimiter {
	return &ReauthLimiter{m: map[uint]*rate.Limiter{}}
}

// Allow reports whether the account may attempt a re-authentication now.
func (r *ReauthLimiter) Allow(adminID uint) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.m[adminID]
	if !ok {
		l = rate.NewLimiter(rate.Every(time.Minute), 5)
		r.m[adminID] = l
	}
	return l.Allow()
}
