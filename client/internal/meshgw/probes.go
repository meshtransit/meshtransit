package meshgw

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
)

// statusTimeout bounds one status read; the stores may wait on the state
// Secret meanwhile.
const statusTimeout = 10 * time.Second

// Counter is one metric the probes serve beside the status.
type Counter struct {
	Name, Help string
	Value      func() uint64
}

// Probes serves the kubelet's probes and metrics from the last status a
// poller read. Reading status can wait on the stores, which may wait on the
// API server, so no probe reads it itself: the kubelet's short timeouts
// would turn a slow API server into a restart. A result older than three
// intervals counts as not ready, so a stuck read cannot leave the pod ready.
type Probes struct {
	status   func(context.Context) (daemon.Status, error)
	interval time.Duration
	counters []Counter
	checks   []check
	clock    func() time.Time
	last     atomic.Pointer[observed]
}

// check is one more condition of readiness, with the reason it gives.
type check struct {
	reason string
	ok     func() bool
}

type observed struct {
	at     time.Time
	ready  bool
	reason string
	status daemon.Status
}

// NewProbes polls status every interval once Poll runs.
func NewProbes(status func(context.Context) (daemon.Status, error), interval time.Duration, counters ...Counter) *Probes {
	probes := &Probes{status: status, interval: interval, counters: counters, clock: time.Now}
	probes.last.Store(&observed{at: probes.clock(), reason: "starting"})
	return probes
}

// Require adds a condition of readiness; reason is reported while it fails.
// Call it before Poll.
func (p *Probes) Require(reason string, ok func() bool) {
	p.checks = append(p.checks, check{reason: reason, ok: ok})
}

// Poll reads the status until ctx ends, then reports not ready.
func (p *Probes) Poll(ctx context.Context) {
	defer p.last.Store(&observed{at: p.clock(), reason: "stopping"})
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		p.observe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *Probes) observe(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	status, err := p.status(ctx)
	if err != nil {
		p.last.Store(&observed{at: p.clock(), reason: "status unavailable"})
		return
	}
	ready, reason := readiness(status)
	for _, required := range p.checks {
		if ready && !required.ok() {
			ready, reason = false, required.reason
		}
	}
	p.last.Store(&observed{at: p.clock(), ready: ready, reason: reason, status: status})
}

// current is the last result, not ready once it is stale.
func (p *Probes) current() observed {
	last := *p.last.Load()
	if last.ready && p.clock().Sub(last.at) > 3*p.interval {
		last.ready, last.reason = false, "status is stale"
	}
	return last
}

// readiness is whether the replica serves: its control session is current,
// or reconnecting with the last map still in force as the daemon reports it
// online, and its data plane works. Idle counts, as a gateway no rule
// reaches yet has no peers; so does waiting for a peer's endpoint.
func readiness(status daemon.Status) (bool, string) {
	switch status.ControlSession {
	case daemon.ControlSessionSynchronized, daemon.ControlSessionReconnecting:
	default:
		return false, "control session " + status.ControlSession
	}
	switch dataplane.State(status.DataPlane) {
	case dataplane.StateFailed, dataplane.StatePolicyUnsupported:
		return false, "data plane " + status.DataPlane
	}
	return true, "ready"
}

// Handler serves /healthz (the process answers), /readyz and /metrics.
func (p *Probes) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		last := p.current()
		if !last.ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = fmt.Fprintln(w, last.reason)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		last := p.current()
		ready := 0
		if last.ready {
			ready = 1
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = fmt.Fprintf(w,
			"# HELP meshgw_ready Whether the gateway serves.\n# TYPE meshgw_ready gauge\nmeshgw_ready %d\n"+
				"# HELP meshgw_peers Peers in the current map.\n# TYPE meshgw_peers gauge\nmeshgw_peers %d\n"+
				"# HELP meshgw_netmap_revision Revision of the current map.\n# TYPE meshgw_netmap_revision gauge\n"+
				"meshgw_netmap_revision %d\n",
			ready, last.status.PeerCount, last.status.NetmapRevision)
		for _, counter := range p.counters {
			_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n",
				counter.Name, counter.Help, counter.Name, counter.Name, counter.Value())
		}
	})
	return mux
}
