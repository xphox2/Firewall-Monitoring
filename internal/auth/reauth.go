package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// reauthBurst / reauthEvery are the per-account budget: a burst of 5
	// attempts, then one per minute.
	reauthBurst = 5
	reauthEvery = time.Minute
	// reauthRefill is how long an untouched limiter takes to refill to a full
	// burst. An entry idle that long is indistinguishable from a fresh one,
	// so sweeping it is lossless — nobody regains budget they had not
	// already regained by waiting.
	reauthRefill = reauthBurst * reauthEvery
	// reauthMaxEntries caps the map (L-10). Keys are authenticated account
	// ids, so reaching it needs that many accounts with live sessions; at the
	// cap the least-recently-used entry — the one closest to full — goes.
	reauthMaxEntries = 10000
)

type reauthEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// ReauthLimiter is the per-account limiter for every re-authentication inside
// an authenticated session — the password (+ TOTP) re-checks behind a
// password change, 2FA setup / disable, a credential reveal, a device purge
// and passkey registration / deletion (D4): a burst of 5 attempts, then one
// per minute, keyed by the session's own account id. It counts every attempt,
// successful or not, and is deliberately SEPARATE from the login lockout: a
// wrong password here never locks the account's login (so a hijacked session
// cannot lock the real operator out), and a login failure never spends this
// budget. The zero value is ready to use.
//
// L-10: entries idle for a full refill are swept (at most once per refill
// window, from Allow — no goroutine to stop) and the map is capped, so ids of
// deleted accounts never accumulate for the life of the process.
type ReauthLimiter struct {
	mu        sync.Mutex
	m         map[uint]*reauthEntry
	lastSweep time.Time
	now       func() time.Time // nil = time.Now (tests inject a clock)
	max       int              // 0 = reauthMaxEntries (tests shrink it)
}

// Allow reports whether the account may attempt a re-authentication now,
// consuming one attempt when it may.
func (r *ReauthLimiter) Allow(adminID uint) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	if r.m == nil {
		r.m = map[uint]*reauthEntry{}
		r.lastSweep = now
	}
	if now.Sub(r.lastSweep) >= reauthRefill {
		for id, e := range r.m {
			if now.Sub(e.lastSeen) >= reauthRefill {
				delete(r.m, id)
			}
		}
		r.lastSweep = now
	}
	e, ok := r.m[adminID]
	if !ok {
		max := r.max
		if max <= 0 {
			max = reauthMaxEntries
		}
		for len(r.m) >= max {
			var oldestID uint
			var oldest time.Time
			first := true
			for id, o := range r.m {
				if first || o.lastSeen.Before(oldest) {
					oldestID, oldest, first = id, o.lastSeen, false
				}
			}
			delete(r.m, oldestID)
		}
		e = &reauthEntry{lim: rate.NewLimiter(rate.Every(reauthEvery), reauthBurst)}
		r.m[adminID] = e
	}
	e.lastSeen = now
	return e.lim.AllowN(now, 1)
}
