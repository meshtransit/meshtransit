package meshgw

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/kubeaudit"
	"meshtransit.net/client/internal/kubeevent"
	"meshtransit.net/client/internal/kubeproxy"
	"meshtransit.net/client/internal/kubetoken"
	"meshtransit.net/client/internal/rbaccheck"
	"meshtransit.net/client/internal/version"
)

const (
	// rbacCheckInterval paces rbaccheck's passes (K1b design §9).
	rbacCheckInterval = 10 * time.Minute
	// checkMintRate and checkMintBurst bound rbaccheck's own minter, apart
	// from the users' (review b4 L4): one token per group, refreshed.
	checkMintRate, checkMintBurst = 2, 20
	// privilegedEventWindow gathers one (Device, group)'s privileged uses
	// into one Event (K1b design §4).
	privilegedEventWindow = 5 * time.Minute
)

// kubeAuditChannels carry the recorder's batches and outcomes to the
// daemon's map stream.
type kubeAuditChannels struct {
	calls   chan controlplane.KubeAuditCall
	reports chan controlplane.KubeAuditReport
}

func newKubeAuditChannels() kubeAuditChannels {
	return kubeAuditChannels{
		calls:   make(chan controlplane.KubeAuditCall),
		reports: make(chan controlplane.KubeAuditReport),
	}
}

// kubeRuntime is a proxying gateway's request path: the proxy, the
// recorder of type A operations, the token minters and the RBAC checker.
type kubeRuntime struct {
	proxy    *kubeproxy.Server
	recorder *kubeaudit.Recorder
	checker  *rbaccheck.Checker
	minters  []*kubetoken.Minter
	listener *KubeProxyListener
	// open is whether the replica takes kubectl, for its listener and its
	// readiness alike.
	open   func() (bool, string)
	logger *slog.Logger
	// apiAudiences are the API server's audiences as the gateway's own
	// token names them, for status.
	apiAudiences []string
	// groupNames are the configured groups, in order, for status;
	// checkGroups the same as rbaccheck checks them, for Core's report.
	groupNames  []string
	checkGroups []rbaccheck.Group
	memory      *memoryWatch
}

// newKubeRuntime builds the request path of a proxying gateway.
//
// boundSecretUID is the UID of the replica's state Secret, which minted
// tokens are bound to.
func newKubeRuntime(cfg Config, service *daemon.Service, coreNow func() time.Time, audits kubeAuditChannels,
	stacks stackSource, boundSecretUID string, memoryLimit int64, logger *slog.Logger,
) (*kubeRuntime, error) {
	kube := cfg.Kube
	if kube.APIServerOverride {
		logger.Warn("the API server is overridden: tests only", "error_code", "kubernetes_api_override",
			"server", kube.APIServer)
	}
	recorderOptions := kubeaudit.DefaultOptions()
	recorderOptions.Calls, recorderOptions.Reports, recorderOptions.CoreNow = audits.calls, audits.reports, coreNow
	recorder, err := kubeaudit.New(recorderOptions)
	if err != nil {
		return nil, fmt.Errorf("meshgw: the audit recorder: %w", err)
	}
	minter, err := newMinter(cfg, boundSecretUID, kubetoken.DefaultOptions())
	if err != nil {
		return nil, err
	}
	checkOptions := kubetoken.DefaultOptions()
	checkOptions.Capacity, checkOptions.Rate, checkOptions.Burst = len(kube.Groups), checkMintRate, checkMintBurst
	checkMinter, err := newMinter(cfg, boundSecretUID, checkOptions)
	if err != nil {
		minter.Close()
		return nil, err
	}
	runtime := &kubeRuntime{
		recorder: recorder, minters: []*kubetoken.Minter{minter, checkMinter}, logger: logger,
		memory: newMemoryWatch(memoryLimit),
	}
	fail := func(err error) (*kubeRuntime, error) {
		runtime.close()
		return nil, err
	}
	reviewer, err := rbaccheck.NewAPIReviewer(kube.APIServer, kube.APICAFile)
	if err != nil {
		return fail(fmt.Errorf("meshgw: %w", err))
	}
	checkGroups := make([]rbaccheck.Group, 0, len(kube.Groups))
	for _, group := range kube.Groups {
		runtime.groupNames = append(runtime.groupNames, group.Name)
		checkGroups = append(checkGroups, rbaccheck.Group{
			Name: group.Name, Privileged: group.Privileged,
			AllowImpersonation: group.AllowImpersonation,
		})
	}
	runtime.checkGroups = checkGroups
	runtime.checker, err = rbaccheck.New(rbaccheck.Options{
		Groups: checkGroups, Reviewer: reviewer, Tokens: &rbaccheck.MinterTokens{Minter: checkMinter},
		Namespace: cfg.Namespace, StatefulSet: kube.StatefulSet, ServiceAccount: kube.ServiceAccount,
		Replicas: kube.Replicas, Secrets: kube.Secrets, GuardedNamespaces: kube.GuardedNamespaces,
		Interval: rbacCheckInterval, Logger: logger.With("component", "rbaccheck"),
	})
	if err != nil {
		return fail(fmt.Errorf("meshgw: %w", err))
	}
	events, err := kubeevent.New(kubeevent.Options{
		Server: kube.APIServer, CAFile: kube.APICAFile,
		TokenFile: kube.APITokenFile, Namespace: cfg.Namespace, Instance: cfg.PodName,
		Window: privilegedEventWindow, Logger: logger.With("component", "kube_events"),
	})
	if err != nil {
		return fail(fmt.Errorf("meshgw: %w", err))
	}
	runtime.apiAudiences = checkAudiences(kube, logger)
	if !buffersFit(memoryLimit, cfg.TCP) {
		logger.Warn("TCP buffers leave less memory than the fewest connections need", "error_code",
			"kubernetes_tcp_buffers_exceed_memory", "receive", cfg.TCP.Receive, "send", cfg.TCP.Send,
			"memory_limit", memoryLimit)
	}
	runtime.proxy, err = kubeproxy.New(kubeproxy.Options{
		Cluster: kube.Cluster, Namespace: cfg.Namespace, Groups: kube.Groups,
		Backend: kube.APIServer, BackendCA: kube.APICAFile,
		Peer: func(source netip.Addr) (kubeproxy.Peer, bool) {
			peer, ok := service.KubernetesPeerAt(source)
			return kubeproxy.Peer{DeviceID: peer.DeviceID, Name: peer.Name, Key: peer.Key, Access: peer.Kubernetes}, ok
		},
		Certificate: service.GatewayCertificate, MapFreshAt: service.MapFreshAt, StaleAfter: kube.StaleAfter,
		CoreNow: coreNow, Verdict: runtime.checker.Verdict, Records: recorder,
		Tokens: kubeproxy.MinterTokens{Minter: minter}, SecretResources: kube.SecretResources,
		Events: events, Wake: runtime.checker.Changes(), Pressure: runtime.memory.Pressure,
		Limits:  limitsFor(memoryLimit, cfg.TCP),
		Version: version.Current().Version, Logger: logger.With("component", "kube_proxy"),
	})
	if err != nil {
		return fail(fmt.Errorf("meshgw: %w", err))
	}
	runtime.open = kubeOpen(service.GatewayCertificate, service.MapFreshAt, kube.StaleAfter, time.Now)
	runtime.listener = &KubeProxyListener{
		Stacks: stacks, Port: uint16(cfg.KubeAPIPort), //nolint:gosec // validated 1-65535
		Server: runtime.proxy,
		Open:   runtime.open,
		Logger: logger.With("component", "kube_api"),
	}
	return runtime, nil
}

// The replica's memory, in the design's terms (§8): a fixed part (token
// cache, map, runtime), then what each connection and each stream to the
// API server may hold at worst. A connection: the larger of its TCP
// receive buffer and HTTP/2's connection window (256 KiB each by default),
// its TCP send buffer (96 KiB), then TLS records and goroutines. A stream:
// its 128 KiB window to the API server and a 32 KiB copy buffer.
const (
	fixedMemory        = 100 << 20
	connectionOverhead = 48 << 10
	streamMemory       = 160 << 10
	// minimumConnections is the floor of a replica's connections.
	minimumConnections = 64
	// streamsShare of what is left after the fixed part goes to streams,
	// the rest to connections.
	streamsShare = 0.4
)

// connectionMemory is what one connection may hold with tcp's buffers:
// 400 KiB with the defaults. HTTP/2 may queue its whole connection window
// whatever the stack's buffer, so received bytes count at least that much
// (review K1c c1 M2).
func connectionMemory(tcp TCPBuffers) float64 {
	return float64(max(tcp.Receive, kubeproxy.ConnectionReceiveWindow) + tcp.Send + connectionOverhead)
}

// buffersFit reports whether the floor of connections fits the memory a
// limit leaves for them with tcp's buffers; a cluster setting very large
// buffers on a small pod is warned at start (review K1c c1 M3).
func buffersFit(memoryLimit int64, tcp TCPBuffers) bool {
	if memoryLimit <= 0 || memoryLimit == math.MaxInt64 {
		return true
	}
	left := max(0, float64(memoryLimit-fixedMemory))
	return minimumConnections*connectionMemory(tcp) <= left*(1-streamsShare)
}

// limitsFor sizes the replica's connections and streams to its soft memory
// limit, at most the design's 1,024 and 2,048 (review TD-CLI-82 M1): with
// the default buffers a 512 MiB pod (435 MiB soft) takes about 510
// connections and 860 streams; a 1 GiB pod (870 MiB soft) 1,024 and about
// 1,970. Larger buffers leave fewer connections (K1c Q88).
func limitsFor(memoryLimit int64, tcp TCPBuffers) kubeproxy.Limits {
	limits := kubeproxy.DefaultLimits()
	if memoryLimit <= 0 || memoryLimit == math.MaxInt64 {
		return limits
	}
	left := max(0, float64(memoryLimit-fixedMemory))
	limits.Streams = clampCount(left*streamsShare/streamMemory, 128, limits.Streams)
	limits.Connections = clampCount(left*(1-streamsShare)/connectionMemory(tcp), minimumConnections,
		limits.Connections)
	return limits
}

func clampCount(value float64, lowest, highest int) int {
	return int(min(float64(highest), max(float64(lowest), value)))
}

// anyGroupEnabled reports whether rbaccheck has turned on any of groups.
func anyGroupEnabled(groups []kubeproxy.Group, verdict func(string) rbaccheck.Verdict) bool {
	for _, group := range groups {
		if verdict(group.Name).Enabled {
			return true
		}
	}
	return false
}

// checkAudiences reads the API server's audiences from the gateway's own
// token and reports, once at start, a cluster whose audiences differ from
// the chart's: every mint would then be refused by the token VAP and every
// group turned off, so the log names the value to set (K1c §7 c2).
//
// The snapshot is taken once: a cluster that changes its API audiences
// shows the new ones after a restart, once the kubelet has refreshed the
// token (up to a day).
func checkAudiences(kube KubeConfig, logger *slog.Logger) []string {
	audiences, err := kubetoken.ReadAudiences(kube.APITokenFile)
	if err != nil {
		logger.Warn("the API server's audiences are unknown", "error_code", "kubernetes_audiences_unknown",
			"token_file", kube.APITokenFile, "error", err)
		return nil
	}
	if len(kube.APIAudiences) > 0 && !kubetoken.SameAudiences(audiences, kube.APIAudiences) {
		logger.Error("the gateway's API token names other audiences than apiServerAudiences admits: set "+
			"apiServerAudiences to the token's", "error_code", "kubernetes_audience_mismatch",
			"token_audiences", audiences, "configured", kube.APIAudiences, "token_file", kube.APITokenFile)
	}
	return audiences
}

// kubeOpen reports whether the replica may take kubectl: a valid
// certificate and a map Core confirmed within staleAfter of now. The
// listener and readiness both ask it (K1c Q87).
func kubeOpen(certificate func() (*tls.Certificate, bool), freshAt func() time.Time, staleAfter time.Duration,
	now func() time.Time,
) func() (bool, string) {
	return func() (bool, string) {
		if _, valid := certificate(); !valid {
			return false, "no valid certificate"
		}
		if fresh := freshAt(); fresh.IsZero() || now().Sub(fresh) > staleAfter {
			return false, "map not confirmed within " + staleAfter.String()
		}
		return true, ""
	}
}

func newMinter(cfg Config, boundSecretUID string, options kubetoken.Options) (*kubetoken.Minter, error) {
	options.Server, options.CAFile, options.TokenFile = cfg.Kube.APIServer, cfg.Kube.APICAFile, cfg.Kube.APITokenFile
	options.Namespace, options.BoundSecret, options.BoundSecretUID = cfg.Namespace, cfg.StateSecret, boundSecretUID
	minter, err := kubetoken.New(options)
	if err != nil {
		return nil, fmt.Errorf("meshgw: the token minter: %w", err)
	}
	return minter, nil
}

// run runs the recorder, the checker and the listener until ctx ends.
func (runtime *kubeRuntime) run(ctx context.Context) {
	var running sync.WaitGroup
	for _, part := range []func(context.Context) error{
		runtime.recorder.Run, runtime.checker.Run,
		runtime.listener.Run, runtime.proxy.Run, runtime.memory.Run,
	} {
		running.Go(func() {
			if err := part(ctx); err != nil && !errors.Is(err, context.Canceled) {
				runtime.logger.Error("kube request path stopped", "error", err)
			}
		})
	}
	running.Wait()
}

func (runtime *kubeRuntime) close() {
	for _, minter := range runtime.minters {
		minter.Close()
	}
}

// kubectlReadiness is what readiness requires of the kubectl path, and the
// metrics it adds.
type kubectlReadiness struct {
	checks   []check
	counters []Counter
	// metrics and status, when set, add to /metrics and /status.
	metrics func(io.Writer)
	status  map[string]func() any
}

// kubectlPath is the gateway's kubectl path: the proxy (K1b) or the K0
// forwarder.
type kubectlPath struct {
	run   func(context.Context)
	close func()
}

// newKubectlPath builds the path cfg.Kube.Mode names. A proxying replica
// is ready while it serves: a valid certificate, a map Core confirmed within
// the stale bound, every address it may listen on listening, and some group
// rbaccheck turned on (K1c Q87,
// replacing Q51's map-blind readiness: the PDB evicts unready pods anyway,
// so readiness need not hide a replica that cannot serve); a passthrough
// one while it listens.
func newKubectlPath(cfg Config, service *daemon.Service, coreNow func() time.Time, audits kubeAuditChannels,
	groups *groupReports, stacks stackSource, boundSecretUID string, memoryLimit int64, logger *slog.Logger,
) (kubectlPath, kubectlReadiness, error) {
	if cfg.Kube.Mode == KubeModeProxy {
		if boundSecretUID == "" {
			return kubectlPath{}, kubectlReadiness{}, errors.New("meshgw: the state Secret has no UID to bind tokens to")
		}
		runtime, err := newKubeRuntime(cfg, service, coreNow, audits, stacks, boundSecretUID, memoryLimit, logger)
		if err != nil {
			return kubectlPath{}, kubectlReadiness{}, err
		}
		groups.bind(runtime.checkGroups, runtime.checker.Verdict, runtime.checker.LastPass)
		return kubectlPath{run: runtime.run, close: runtime.close}, kubectlReadiness{checks: []check{
			{open: runtime.open},
			{reason: "kube API cannot listen", ok: func() bool { return !runtime.listener.BindFailing() }},
			// A replica whose every group is off, or not checked yet, serves
			// no one: a bad value (a wrong audience) stops a rollout at its
			// first replica (K1c Q87).
			{reason: "no Kubernetes group enabled", ok: func() bool { return anyGroupEnabled(cfg.Kube.Groups, runtime.checker.Verdict) }},
		}, metrics: runtime.writeMetrics, status: map[string]func() any{"kube": runtime.status}}, nil
	}
	if cfg.JoinKeyFile != "" {
		// Gone at K1f; support sees it on every start (review L8).
		logger.Warn("kubectl passes through to the API server unchecked", "error_code",
			"kubernetes_passthrough_mode")
	}
	forwarder := &KubeAPIForwarder{
		Stacks:         stacks,
		Port:           uint16(cfg.KubeAPIPort), //nolint:gosec // validated 1-65535
		Backend:        cfg.KubeAPIBackend,
		MaxConnections: DefaultMaxKubeAPIConnections,
		PeerAt:         service.PeerAt,
		Now:            coreNow,
		Logger:         logger.With("component", "kube_api"),
	}
	return kubectlPath{run: func(ctx context.Context) { _ = forwarder.Run(ctx) }, close: func() {}},
		kubectlReadiness{
			// K0 serves kubectl: a replica not listening for it is not ready.
			checks: []check{{reason: "kube API not listening", ok: forwarder.Listening}},
			status: map[string]func() any{"kube": func() any {
				return map[string]any{"mode": KubeModePassthrough, "listening": forwarder.Listening()}
			}},
			counters: []Counter{{
				Name: "meshgw_kube_api_connections_total", Help: "kubectl connections carried.",
				Value: forwarder.Total,
			}},
		}, nil
}
