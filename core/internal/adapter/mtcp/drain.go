package mtcp

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// drainWorkers bounds the concurrent goodbyes of a drain or shed: one slow
// client holds its writer for up to writeTimeout.
const drainWorkers = 64

// shedMinimumAge spares young sessions when shedding: a node still
// registering or receiving its first map gains nothing from moving, and a
// node that just moved here is not moved straight on.
const shedMinimumAge = 30 * time.Second

var (
	// errShed ends a session this replica asked to reconnect elsewhere.
	errShed = errors.New("mtcp: session shed to rebalance")
)

// Sessions returns how many sessions are established on this replica.
func (server *Server) Sessions() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.live)
}

// Shed asks up to count sessions, chosen at random, to reconnect within
// window (each at its own random delay, so they do not return together)
// and ends them. It returns how many it shed. Nodes keep their tunnels
// while they reconnect; the load balancer may place them on another
// replica.
func (server *Server) Shed(ctx context.Context, count int, window time.Duration) int {
	if count <= 0 {
		return 0
	}
	server.mu.Lock()
	if server.shutdown {
		server.mu.Unlock()
		return 0
	}
	sessions := server.liveSessionsLocked()
	server.mu.Unlock()
	oldest := server.options.Now().Add(-shedMinimumAge).UnixNano()
	sessions = slices.DeleteFunc(sessions, func(session *Session) bool {
		return session.established.Load() > oldest
	})
	rand.Shuffle(len(sessions), func(i, j int) { sessions[i], sessions[j] = sessions[j], sessions[i] }) //nolint:gosec // choosing whom to shed needs no secrecy
	sessions = sessions[:min(count, len(sessions))]
	server.sayGoodbye(ctx, sessions, window, "the control replica is rebalancing", errShed)
	server.options.Metrics.shed(len(sessions))
	return len(sessions)
}

func (server *Server) liveSessionsLocked() []*Session {
	sessions := make([]*Session, 0, len(server.live))
	for session := range server.live {
		sessions = append(sessions, session)
	}
	return sessions
}

// sayGoodbye sends each session a RECONNECT at a random delay within window
// and ends it, a bounded number at a time.
func (server *Server) sayGoodbye(ctx context.Context, sessions []*Session, window time.Duration, reason string,
	cause error) {
	work := make(chan *Session)
	var workers sync.WaitGroup
	for range min(drainWorkers, len(sessions)) {
		workers.Go(func() {
			for session := range work {
				session.reconnect(jitter(window), reason, cause)
			}
		})
	}
	for _, session := range sessions {
		select {
		case work <- session:
		case <-ctx.Done():
			session.close(cause) // out of time: end it without a goodbye
		}
	}
	close(work)
	workers.Wait()
}

// reconnect asks the node to come back after retry and ends the session.
func (session *Session) reconnect(retry time.Duration, reason string, cause error) {
	_ = session.Send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_RECONNECT,
		Reason: reason, RetryAfterMs: uint32(min(retry.Milliseconds(), int64(^uint32(0))))}) //nolint:gosec // bounded
	session.close(cause)
}

// jitter returns a uniformly random delay in [0, window).
func jitter(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	return rand.N(window) //nolint:gosec // spreading reconnects needs no secrecy
}
