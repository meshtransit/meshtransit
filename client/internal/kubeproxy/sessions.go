package kubeproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// sweepInterval paces the sweep of open sessions: a session whose access
// ended is cut within it, well inside the design's 5 s (K1b design §8).
const sweepInterval = time.Second

// Session kinds, as the registry counts them.
const (
	kindRequest = "request"
	kindWatch   = "watch"
	kindStream  = "stream" // a log followed
	kindUpgrade = "upgrade"
)

// Reasons a session is cut, as logs and metrics name them.
const (
	cutStale         = "stale_map"
	cutIdentity      = "identity"
	cutRevoked       = "revoked"
	cutGroupOff      = "group_off"
	cutImpersonation = "impersonation_off"
	cutProfile       = "profile_changed"
	cutWithheld      = "kubernetes_withheld"
)

// errSessionCut is what a cut session's context cause is: a sessionCut,
// which names the reason.
var errSessionCut = errors.New("kubeproxy: the session's access ended")

// sessionCut is the cause a cut session's context carries.
type sessionCut struct{ reason string }

func (cut sessionCut) Error() string        { return errSessionCut.Error() + ": " + cut.reason }
func (cut sessionCut) Is(target error) bool { return target == errSessionCut }

// cutReasonOf is why ctx's session was cut, or "" if it was not.
func cutReasonOf(ctx context.Context) string {
	var cut sessionCut
	if errors.As(context.Cause(ctx), &cut) {
		return cut.reason
	}
	return ""
}

// cutBuckets bound the histogram of how long a cut session took to end,
// in seconds.
var cutBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 5, 10}

// session is one request, watch or upgraded connection in flight, with
// what it was allowed by (K1b design §8, K1-I4).
type session struct {
	device string
	key    [32]byte
	source netip.Addr
	group  Group
	kind   string
	// impersonating: the request kept Impersonate-* headers, which the
	// group's verdict must still allow.
	impersonating bool
	// check is the request as profiles read it, which the sweep decides
	// again (K2 §9.3): a resource whose scope was not asked then (a whole
	// grant) is unknown, so a whole grant that narrows cuts it.
	check  profileCheck
	cancel context.CancelCauseFunc
	// close ends an upgraded HTTP/1.1 connection, which outlives its
	// request.
	close func()

	// Guarded by the registry's lock.
	cutReason string
	cutAt     time.Time
	auditID   [16]byte
}

// registry is the open sessions.
type registry struct {
	mu   sync.Mutex
	live map[*session]struct{}
	// cuts counts sessions cut, by reason; cutSeconds is the histogram of
	// how long they took to end once cut.
	cuts       map[string]uint64
	cutSeconds histogram
	// devices counts each Device's open sessions by kind, for the limits.
	devices map[string]map[string]int
}

func newRegistry() *registry {
	return &registry{
		live: map[*session]struct{}{}, cuts: map[string]uint64{},
		cutSeconds: histogram{bounds: cutBuckets, counts: make([]uint64, len(cutBuckets)+1)},
		devices:    map[string]map[string]int{},
	}
}

// add registers a session within the limits; done removes it once it
// ended. A session past a limit is not added: limit names it.
func (sessions *registry) add(held *session, limits Limits) (done func(), limit string) {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	if limit := sessions.admit(held, limits); limit != "" {
		return nil, limit
	}
	sessions.live[held] = struct{}{}
	kinds := sessions.devices[held.device]
	if kinds == nil {
		kinds = map[string]int{}
		sessions.devices[held.device] = kinds
	}
	kinds[held.kind]++
	return func() {
		sessions.mu.Lock()
		defer sessions.mu.Unlock()
		delete(sessions.live, held)
		if kinds[held.kind]--; kinds[held.kind] == 0 {
			delete(kinds, held.kind)
			if len(kinds) == 0 {
				delete(sessions.devices, held.device)
			}
		}
		if held.cutReason != "" {
			sessions.cutSeconds.observe(time.Since(held.cutAt).Seconds())
		}
	}, ""
}

// open is the sessions now, to check outside the lock.
func (sessions *registry) open() []*session {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	open := make([]*session, 0, len(sessions.live))
	for held := range sessions.live {
		if held.cutReason == "" {
			open = append(open, held)
		}
	}
	return open
}

// setAuditID names a session's record, for its cut's log line.
func (sessions *registry) setAuditID(held *session, auditID [16]byte) {
	sessions.mu.Lock()
	held.auditID = auditID
	sessions.mu.Unlock()
}

// cut ends a session still open, once: its request's context is
// cancelled, and an upgraded connection closed. One that ended since the
// sweep's snapshot is left alone, so its connection's next request is not
// closed with it (review b6a M2). It returns the session's record.
func (sessions *registry) cut(held *session, reason string) ([16]byte, bool) {
	sessions.mu.Lock()
	if _, live := sessions.live[held]; !live || held.cutReason != "" {
		sessions.mu.Unlock()
		return [16]byte{}, false
	}
	held.cutReason, held.cutAt = reason, time.Now()
	sessions.cuts[reason]++
	auditID := held.auditID
	sessions.mu.Unlock()
	held.cancel(sessionCut{reason: reason})
	if held.close != nil {
		held.close()
	}
	return auditID, true
}

// SessionStats are the open sessions by kind, the sessions cut by reason
// and how long cut sessions took to end.
type SessionStats struct {
	Open       map[string]int
	Cut        map[string]uint64
	CutSeconds HistogramSnapshot
}

func (sessions *registry) stats() SessionStats {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	stats := SessionStats{
		Open: map[string]int{kindRequest: 0, kindWatch: 0, kindStream: 0, kindUpgrade: 0},
		Cut:  make(map[string]uint64, len(sessions.cuts)), CutSeconds: sessions.cutSeconds.snapshot(),
	}
	for held := range sessions.live {
		stats.Open[held.kind]++
	}
	for reason, count := range sessions.cuts {
		stats.Cut[reason] = count
	}
	return stats
}

// Sessions reports the open and cut sessions.
func (server *Server) Sessions() SessionStats { return server.sessions.stats() }

// Run sweeps the open sessions until ctx ends: every second, and at once
// when Options.Wake signals (a group's verdict changed).
func (server *Server) Run(ctx context.Context) error {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-server.options.Wake:
		}
		server.Sweep()
	}
}

// Sweep cuts every open session whose access ended.
func (server *Server) Sweep() {
	for _, held := range server.sessions.open() {
		reason := server.ended(held)
		if reason == "" {
			continue
		}
		if auditID, cut := server.sessions.cut(held, reason); cut {
			server.options.Logger.Info("kube session cut", "audit_id", formatAuditID(auditID),
				"device_id", held.device, "group", held.group.Name, "kind", held.kind, "reason", reason)
		}
	}
}

// ended says why a session may no longer go on, or "" while it may: the
// map is stale, its address is another key's, its Device lost the group or
// its grant expired, or the group is turned off.
func (server *Server) ended(held *session) string {
	if server.stale() {
		return cutStale
	}
	peer, ok := server.options.Peer(held.source)
	switch {
	case !ok || peer.DeviceID != held.device || peer.Key != held.key:
		return cutIdentity
	case peer.Withheld:
		return cutWithheld
	case !slices.Contains(peer.Access.HeldAt(server.options.CoreNow()), held.group.Name):
		return cutRevoked
	case held.group.Privileged && server.privileged(peer, held.group) != "":
		return cutRevoked
	case !decide(peer, held.group, held.check, server.options.CoreNow()).allowed:
		return cutProfile
	}
	verdict := server.options.Verdict(held.group.Name)
	switch {
	case !verdict.Enabled:
		return cutGroupOff
	case held.impersonating && !verdict.Impersonation:
		return cutImpersonation
	}
	return ""
}

// cutAnswer is what a request whose session ended is answered. One Core
// already recorded is not counted again as a denial (re-review b6a L2).
func (server *Server) cutAnswer(w http.ResponseWriter, device string, group Group, reason string, recorded bool) {
	denial, code, message, wait := "not_granted", http.StatusForbidden, "the Device's access to group "+group.Name+
		" ended", time.Duration(0)
	switch reason {
	case cutStale:
		denial, code, message, wait = "stale", http.StatusServiceUnavailable,
			"the gateway has no current map from MeshTransit", time.Second
	case cutGroupOff:
		denial, message = "forbidden", fmt.Sprintf("group %q is turned off by the gateway: %s", group.Name,
			server.options.Verdict(group.Name).Reason)
	case cutImpersonation:
		denial, message = "forbidden", fmt.Sprintf("group %q may no longer impersonate", group.Name)
	case cutWithheld:
		denial, code, message, wait = "stale", http.StatusServiceUnavailable,
			"the gateway's map from MeshTransit is unusable; it asked for a new one", time.Second
	case cutProfile:
		message = "the Device's access profile for group " + group.Name + " no longer allows this request"
	}
	if recorded {
		refuse(w, code, message, wait)
		return
	}
	server.deny(w, device, denial, code, message, wait)
}

// histogram counts observations into buckets: counts[i] those at or under
// bounds[i], the last those above every bound.
type histogram struct {
	bounds []float64
	counts []uint64
	sum    float64
}

func (h *histogram) observe(value float64) {
	index, _ := slices.BinarySearch(h.bounds, value)
	h.counts[index]++
	h.sum += value
}

// HistogramSnapshot is a histogram's cumulative counts, as Prometheus
// serves them.
type HistogramSnapshot struct {
	Bounds     []float64
	Cumulative []uint64 // per bound, then +Inf
	Sum        float64
}

func (h *histogram) snapshot() HistogramSnapshot {
	cumulative := make([]uint64, len(h.counts))
	var total uint64
	for index, count := range h.counts {
		total += count
		cumulative[index] = total
	}
	return HistogramSnapshot{Bounds: slices.Clone(h.bounds), Cumulative: cumulative, Sum: h.sum}
}
