package meshgw

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// kubeServeCheck is how often the listener checks whether it may serve.
const kubeServeCheck = time.Second

// kubeServer is kubeproxy.Server as the listener sees it.
type kubeServer interface {
	Serve(ctx context.Context, listener net.Listener) error
}

// KubeProxyListener serves the proxy on the gateway's mesh addresses while
// it may: a valid certificate, and a map Core confirmed within staleAfter
// (K1b design §3). Otherwise its listeners and every connection close, so
// the stack answers a reset and client-go tries the cluster name's next
// address, another replica. An address that fails to bind is tried again
// with a growing wait, leaving the others serving (review b5b M2).
type KubeProxyListener struct {
	Stacks stackSource
	Port   uint16
	Server kubeServer
	// Open reports whether the replica may serve, else why not.
	Open   func() (bool, string)
	Logger *slog.Logger

	listening atomic.Bool
	// bindFailing: the replica may serve but an address does not listen.
	bindFailing atomic.Bool
	// reason is why the listener is closed; nil while it listens.
	reason atomic.Pointer[string]
}

// Listening reports whether the proxy takes connections on every address
// of the current stack.
func (l *KubeProxyListener) Listening() bool { return l.listening.Load() }

// BindFailing reports a replica that may serve with an address it cannot
// listen on: a local fault, which readiness reports (review b5b M3).
func (l *KubeProxyListener) BindFailing() bool { return l.bindFailing.Load() }

// ClosedReason is why the listener is closed, empty while it listens.
func (l *KubeProxyListener) ClosedReason() string {
	if reason := l.reason.Load(); reason != nil {
		return *reason
	}
	return ""
}

// serving is the proxy on one stack: the addresses that listen, and when
// the others are tried again.
type serving struct {
	stack   Stack
	ctx     context.Context
	stop    context.CancelFunc
	done    sync.WaitGroup
	bound   map[netip.Addr]bool
	retryAt time.Time
	wait    time.Duration
}

// servedExit is a server that returned while its serving went on.
type servedExit struct {
	running *serving
	address netip.Addr
}

func (s *serving) close() {
	if s == nil {
		return
	}
	s.stop()
	s.done.Wait()
}

func (s *serving) complete() bool { return len(s.bound) == len(s.stack.Addresses) && len(s.bound) > 0 }

// Run serves until ctx ends, opening and closing with Open, binding again
// when the stack changes, and trying addresses that failed to bind again.
func (l *KubeProxyListener) Run(ctx context.Context) error {
	var current *serving
	exited := make(chan servedExit)
	defer func() {
		l.listening.Store(false)
		current.close()
	}()
	ticker := time.NewTicker(kubeServeCheck)
	defer ticker.Stop()
	l.setReason("starting")
	for {
		stack, haveStack := l.Stacks.Current()
		open, why := l.Open()
		if !haveStack {
			open, why = false, "no mesh address"
		}
		switch {
		case !open:
			if current != nil {
				current.close()
				current = nil
				l.Logger.Warn("kube API listener closed", "error_code", "kubernetes_listener_closed", "reason", why)
			}
			l.setReason(why)
		case current == nil || current.stack.Retired != stack.Retired:
			current.close()
			current = l.start(ctx, stack)
			l.bindMissing(current, exited)
		case !current.complete() && !time.Now().Before(current.retryAt):
			l.bindMissing(current, exited)
		}
		if current != nil {
			l.reason.Store(nil)
		}
		l.listening.Store(current != nil && current.complete())
		l.bindFailing.Store(current != nil && !current.complete())
		select {
		case <-ctx.Done():
			return nil
		case <-l.Stacks.Changes():
		case <-ticker.C:
		case gone := <-exited:
			// A server that stopped on its own is listened for again.
			if gone.running == current && current.ctx.Err() == nil {
				// After the same wait as a failed bind, so a server that keeps
				// stopping is not bound again in a loop (re-review b5b L1).
				delete(current.bound, gone.address)
				current.retryAt = time.Now().Add(current.wait)
				current.wait = min(2*current.wait, listenRetryMax)
			}
		}
	}
}

// setReason publishes a fresh copy, never a variable the loop writes again
// (review b5b M1).
func (l *KubeProxyListener) setReason(reason string) { l.reason.Store(&reason) }

func (l *KubeProxyListener) start(ctx context.Context, stack Stack) *serving {
	serveCtx, stop := context.WithCancel(ctx)
	return &serving{stack: stack, ctx: serveCtx, stop: stop, bound: map[netip.Addr]bool{}, wait: listenRetryFirst}
}

// bindMissing listens on the stack's addresses not yet listening, and sets
// when to try the rest again.
func (l *KubeProxyListener) bindMissing(running *serving, exited chan<- servedExit) {
	for _, address := range running.stack.Addresses {
		if running.bound[address] {
			continue
		}
		listened, err := running.stack.Net.ListenTCPAddrPort(netip.AddrPortFrom(address, l.Port))
		if err != nil {
			l.Logger.Error("kube API listener failed", "address", address, "port", l.Port, "error", err,
				"retry_in", running.wait)
			continue
		}
		running.bound[address] = true
		l.Logger.Info("kube API listening", "address", address, "port", l.Port, "mode", KubeModeProxy)
		running.done.Go(func() {
			if err := l.Server.Serve(running.ctx, listened); err != nil && running.ctx.Err() == nil {
				l.Logger.Error("kube API server stopped", "address", address, "error", err)
			}
			_ = listened.Close()
			select {
			case exited <- servedExit{running: running, address: address}:
			case <-running.ctx.Done():
			}
		})
	}
	if running.complete() {
		running.wait = listenRetryFirst
		return
	}
	running.retryAt = time.Now().Add(running.wait)
	running.wait = min(2*running.wait, listenRetryMax)
}
