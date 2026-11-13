package localapi

import (
	"strconv"
	"sync"

	"golang.org/x/time/rate"
)

// maxLimitedCallers bounds the callers callerLimits remembers; past it, it
// starts over (each caller then has a full burst again).
const maxLimitedCallers = 256

// callerLimits is one rate limiter per local caller (a Windows user SID or
// a Unix uid): one caller's loop does not lock the others out.
type callerLimits struct {
	mu       sync.Mutex
	limit    rate.Limit
	burst    int
	limiters map[string]*rate.Limiter
}

func newCallerLimits(limit rate.Limit, burst int) *callerLimits {
	return &callerLimits{limit: limit, burst: burst, limiters: make(map[string]*rate.Limiter)}
}

// allow reports whether peer may make one more request now.
func (c *callerLimits) allow(peer peerIdentity) bool {
	key := peer.userSID
	if key == "" {
		key = "uid:" + strconv.FormatUint(uint64(peer.uid), 10)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	limiter, found := c.limiters[key]
	if !found {
		if len(c.limiters) >= maxLimitedCallers {
			clear(c.limiters)
		}
		limiter = rate.NewLimiter(c.limit, c.burst)
		c.limiters[key] = limiter
	}
	return limiter.Allow()
}
