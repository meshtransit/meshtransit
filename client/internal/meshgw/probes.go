package meshgw

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
)

// statusTimeout bounds one status read; the stores may wait on the state
// Secret meanwhile.
const statusTimeout = 10 * time.Second

// staleMapAfter is how long a map may go unconfirmed (MapFresh) before the
// gateway logs it; K1b will refuse requests past its staleAfter.
const staleMapAfter = 5 * time.Minute

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
	// logger, when set, reports a map that went unconfirmed past
	// staleMapAfter, and when it is confirmed again; stale is whether the
	// last observation was.
	logger *slog.Logger
	stale  bool
	// started is when the probes were made; unconfirmed whether a map
	// never confirmed was reported.
	started     time.Time
	unconfirmed bool
	// metrics write more metrics; reports are /status's parts, by name.
	metrics []func(io.Writer)
	reports map[string]func() any
}

// check is one more condition of readiness, with the reason it gives;
// open, when set, is used instead of ok and gives its own reason.
type check struct {
	reason string
	ok     func() bool
	open   func() (bool, string)
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
	probes.started = probes.clock()
	probes.last.Store(&observed{at: probes.clock(), reason: "starting"})
	return probes
}

// Require adds a condition of readiness; reason is reported while it fails.
// Call it before Poll.
func (p *Probes) Require(reason string, ok func() bool) {
	p.requireAll([]check{{reason: reason, ok: ok}})
}

// requireAll adds conditions as they are, an open check's own reason
// included (a copy through Require dropped it: K1c c4). Call it before Poll.
func (p *Probes) requireAll(checks []check) { p.checks = append(p.checks, checks...) }

// AddMetrics adds metrics /metrics writes. Call it before Handler.
func (p *Probes) AddMetrics(write func(io.Writer)) { p.metrics = append(p.metrics, write) }

// AddStatus adds a part to /status, read at each request. Call it before
// Handler.
func (p *Probes) AddStatus(name string, report func() any) {
	if p.reports == nil {
		p.reports = map[string]func() any{}
	}
	p.reports[name] = report
}

// LogStaleMap makes the poller log a map Core has not confirmed current for
// staleMapAfter (K1a3 §5.3). Call it before Poll.
func (p *Probes) LogStaleMap(logger *slog.Logger) { p.logger = logger }

// mapAge is how long ago Core last confirmed the map current; false before
// any confirmation.
func (p *Probes) mapAge(status daemon.Status) (time.Duration, bool) {
	if status.MapFreshAt.IsZero() {
		return 0, false
	}
	return max(p.clock().Sub(status.MapFreshAt), 0), true
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
		if !ready {
			break
		}
		switch {
		case required.open != nil:
			if ok, why := required.open(); !ok {
				ready, reason = false, why
			}
		case required.ok == nil:
			// A wiring mistake: unready, and saying so (review c4 M2).
			ready, reason = false, "readiness check has no condition"
		case !required.ok():
			ready, reason = false, required.reason
		}
	}
	p.last.Store(&observed{at: p.clock(), ready: ready, reason: reason, status: status})
	p.reportStaleness(status)
}

// reportStaleness logs a map crossing staleMapAfter either way.
func (p *Probes) reportStaleness(status daemon.Status) {
	age, confirmed := p.mapAge(status)
	if p.logger == nil {
		return
	}
	if !confirmed {
		// A Core before K1a3c, or a map that withholds its peers' access,
		// is never confirmed: said once.
		if !p.unconfirmed && p.clock().Sub(p.started) > staleMapAfter {
			p.unconfirmed = true
			p.logger.Warn("map never confirmed current")
		}
		return
	}
	switch stale := age > staleMapAfter; {
	case stale && !p.stale:
		p.logger.Warn("map not confirmed current", "age", age.Round(time.Second).String())
	case !stale && p.stale:
		p.logger.Info("map confirmed current again")
	}
	p.stale = age > staleMapAfter
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
//
// Connecting is not ready even after an earlier map: the daemon tears its
// data plane down before it rebuilds the stream (review K1c c1 H1); the
// probe's failure threshold absorbs a short rebuild.
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
		if age, confirmed := p.mapAge(last.status); confirmed {
			_, _ = fmt.Fprintf(w, "# HELP meshgw_map_age_seconds Seconds since Core last confirmed the map current.\n"+
				"# TYPE meshgw_map_age_seconds gauge\nmeshgw_map_age_seconds %d\n", int64(age.Seconds()))
		}
		writeCertificateMetrics(w, last.status.GatewayCertificate)
		for _, counter := range p.counters {
			_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n",
				counter.Name, counter.Help, counter.Name, counter.Name, counter.Value())
		}
		for _, write := range p.metrics {
			write(w)
		}
	})
	// /status is the probes' port only: never on the mesh. It names groups
	// and why they are off, never a token or key (K1b design §11).
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		last := p.current()
		report := map[string]any{"ready": last.ready, "reason": last.reason}
		for name, part := range p.reports {
			report[name] = part()
		}
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(report)
	})
	return mux
}
