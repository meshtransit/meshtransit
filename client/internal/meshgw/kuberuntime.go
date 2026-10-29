package meshgw

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	return kubeAuditChannels{calls: make(chan controlplane.KubeAuditCall),
		reports: make(chan controlplane.KubeAuditReport)}
}

// kubeRuntime is a proxying gateway's request path: the proxy, the
// recorder of type A operations, the token minters and the RBAC checker.
type kubeRuntime struct {
	proxy    *kubeproxy.Server
	recorder *kubeaudit.Recorder
	checker  *rbaccheck.Checker
	minters  []*kubetoken.Minter
	listener *KubeProxyListener
	logger   *slog.Logger
	// groupNames are the configured groups, in order, for status.
	groupNames []string
}

// newKubeRuntime builds the request path of a proxying gateway.
//
// boundSecretUID is the UID of the replica's state Secret, which minted
// tokens are bound to.
func newKubeRuntime(cfg Config, service *daemon.Service, coreNow func() time.Time, audits kubeAuditChannels,
	stacks stackSource, boundSecretUID string, logger *slog.Logger,
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
	runtime := &kubeRuntime{recorder: recorder, minters: []*kubetoken.Minter{minter, checkMinter}, logger: logger}
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
		checkGroups = append(checkGroups, rbaccheck.Group{Name: group.Name, Privileged: group.Privileged,
			AllowImpersonation: group.AllowImpersonation})
	}
	runtime.checker, err = rbaccheck.New(rbaccheck.Options{
		Groups: checkGroups, Reviewer: reviewer, Tokens: &rbaccheck.MinterTokens{Minter: checkMinter},
		Namespace: cfg.Namespace, StatefulSet: kube.StatefulSet, ServiceAccount: kube.ServiceAccount,
		Replicas: kube.Replicas, Secrets: kube.Secrets, GuardedNamespaces: kube.GuardedNamespaces,
		Interval: rbacCheckInterval, Logger: logger.With("component", "rbaccheck"),
	})
	if err != nil {
		return fail(fmt.Errorf("meshgw: %w", err))
	}
	events, err := kubeevent.New(kubeevent.Options{Server: kube.APIServer, CAFile: kube.APICAFile,
		TokenFile: kube.APITokenFile, Namespace: cfg.Namespace, Instance: cfg.PodName,
		Window: privilegedEventWindow, Logger: logger.With("component", "kube_events")})
	if err != nil {
		return fail(fmt.Errorf("meshgw: %w", err))
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
		Events: events, Wake: runtime.checker.Changes(),
		Version: version.Current().Version, Logger: logger.With("component", "kube_proxy"),
	})
	if err != nil {
		return fail(fmt.Errorf("meshgw: %w", err))
	}
	runtime.listener = &KubeProxyListener{
		Stacks: stacks, Port: uint16(cfg.KubeAPIPort), //nolint:gosec // validated 1-65535
		Server: runtime.proxy,
		Open:   kubeOpen(service.GatewayCertificate, service.MapFreshAt, kube.StaleAfter),
		Logger: logger.With("component", "kube_api"),
	}
	return runtime, nil
}

// kubeOpen reports whether the replica may take kubectl: a valid
// certificate and a map Core confirmed within staleAfter.
func kubeOpen(certificate func() (*tls.Certificate, bool), freshAt func() time.Time, staleAfter time.Duration,
) func() (bool, string) {
	return func() (bool, string) {
		if _, valid := certificate(); !valid {
			return false, "no valid certificate"
		}
		if fresh := freshAt(); fresh.IsZero() || time.Since(fresh) > staleAfter {
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
	for _, part := range []func(context.Context) error{runtime.recorder.Run, runtime.checker.Run,
		runtime.listener.Run, runtime.proxy.Run} {
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
// is ready with a valid certificate and every address it may listen on
// listening, whatever Core's state or the map's age (Q51); a passthrough
// one while it listens.
func newKubectlPath(cfg Config, service *daemon.Service, coreNow func() time.Time, audits kubeAuditChannels,
	stacks stackSource, boundSecretUID string, logger *slog.Logger,
) (kubectlPath, kubectlReadiness, error) {
	if cfg.Kube.Mode == KubeModeProxy {
		if boundSecretUID == "" {
			return kubectlPath{}, kubectlReadiness{}, errors.New("meshgw: the state Secret has no UID to bind tokens to")
		}
		runtime, err := newKubeRuntime(cfg, service, coreNow, audits, stacks, boundSecretUID, logger)
		if err != nil {
			return kubectlPath{}, kubectlReadiness{}, err
		}
		return kubectlPath{run: runtime.run, close: runtime.close}, kubectlReadiness{checks: []check{
			{reason: "no valid certificate", ok: func() bool { _, valid := service.GatewayCertificate(); return valid }},
			{reason: "kube API cannot listen", ok: func() bool { return !runtime.listener.BindFailing() }},
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
			counters: []Counter{{Name: "meshgw_kube_api_connections_total", Help: "kubectl connections carried.",
				Value: forwarder.Total}},
		}, nil
}
