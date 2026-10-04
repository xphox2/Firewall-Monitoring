package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ReauthLimiter is the per-account limiter for every re-authentication inside
// an authenticated session — the password (+ TOTP) re-checks behind a
// password change, 2FA setup / disable, a credential reveal, a device purge
// and passkey registration / deletion (D4): a burst of 5 attempts, then one
// per minute, keyed by the session's own account id. It counts every attempt,
// successful or not, and is deliberately SEPARATE from the login lockout: a
// wrong password here never locks the account's login (so a hijacked session
// cannot lock the real operator out), and a login failure never spends this
// budget. The zero value is ready to use.
type ReauthLimiter struct {
	mu sync.Mutex
	m  map[uint]*rate.Limiter
}

// Allow reports whether the account may attempt a re-authentication now,
// consuming one attempt when it may.
func (r *ReauthLimiter) Allow(adminID uint) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[uint]*rate.Limiter{}
	}
	l, ok := r.m[adminID]
	if !ok {
		l = rate.NewLimiter(rate.Every(time.Minute), 5)
		r.m[adminID] = l
	}
	return l.Allow()
}
