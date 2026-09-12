package broker

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyedLimiter gives every distinct key (a source IP or a login_hint) its own token bucket.
type keyedLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	idleTTL time.Duration
	entries map[string]*limiterEntry
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newKeyedLimiter(r rate.Limit, burst int, idleTTL time.Duration) *keyedLimiter {
	return &keyedLimiter{limit: r, burst: burst, idleTTL: idleTTL, entries: make(map[string]*limiterEntry)}
}

// Allow reports whether an event for key may proceed now, consuming a token if so.
func (k *keyedLimiter) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := time.Now()
	k.sweepLocked(now)

	e, ok := k.entries[key]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(k.limit, k.burst)}
		k.entries[key] = e
	}
	e.lastSeen = now
	return e.limiter.Allow()
}

func (k *keyedLimiter) sweepLocked(now time.Time) {
	for key, e := range k.entries {
		if now.Sub(e.lastSeen) > k.idleTTL {
			delete(k.entries, key)
		}
	}
}
