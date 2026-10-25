package meshgw

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/daemon"
)

const (
	// DefaultMaxKubeAPIConnections bounds the kubectl connections one
	// replica carries. Each holds about 2 MiB of stack buffers at worst, so
	// this fits the pod's 512 MiB limit with room for the rest.
	DefaultMaxKubeAPIConnections = 128
	kubeAPIDialTimeout           = 10 * time.Second
	// halfClosedTimeout bounds how long one direction stays open after the
	// other ended: a vanished laptop would otherwise hold its slot for good,
	// as the stack sends no keepalives.
	halfClosedTimeout = 2 * time.Minute
	listenRetryFirst  = time.Second
	listenRetryMax    = 30 * time.Second
	acceptRetry       = 100 * time.Millisecond
)

// stackSource is the gateway's stacks as the forwarder sees them.
type stackSource interface {
	Current() (Stack, bool)
	Changes() <-chan struct{}
}

// KubeAPIForwarder takes kubectl connections on the gateway's mesh addresses
// and passes each, as plain TCP, to the cluster's API server (k8s-gateway-plan
// §0). It never ends TLS: kubectl talks to the API server with its own
// credentials, and the API server's RBAC decides what it may do. The mesh
// decides who reaches the port at all, through Policy on the gateway's
// packet filter. The API server sees only the gateway's pod address, so the
// forwarder's log, which names each connection's Device, is what ties a
// session to a Device.
type KubeAPIForwarder struct {
	Stacks stackSource
	// Port is where kubectl connects on the mesh addresses.
	Port uint16
	// Backend is the API server's host:port inside the cluster.
	Backend string
	// MaxConnections bounds open connections; past it new ones are closed.
	MaxConnections int
	// PeerAt names the map's Device at a connection's source address.
	PeerAt func(netip.Addr) (daemon.PeerView, bool)
	Logger *slog.Logger

	open      atomic.Int64
	total     atomic.Uint64
	listening atomic.Bool
	conns     sync.Map // net.Conn -> struct{}, closed when the forwarder stops
}

// Total counts the connections passed to the API server.
func (f *KubeAPIForwarder) Total() uint64 { return f.total.Load() }

// Listening reports whether the forwarder takes connections on every
// address of the current stack, for readiness.
func (f *KubeAPIForwarder) Listening() bool { return f.listening.Load() }

// listener is a mesh listener the forwarder knows it closed, as gonet's
// errors do not say so.
type listener struct {
	net.Listener
	closed atomic.Bool
}

func (l *listener) close() {
	l.closed.Store(true)
	_ = l.Close()
}

// Run listens on the current stack until ctx ends, binding again whenever
// the stack changes or a bind failed, and closes every connection before it
// returns. A signal that leaves the same stack keeps its listeners: closing
// one would reset connections still waiting to be accepted.
func (f *KubeAPIForwarder) Run(ctx context.Context) error {
	var handlers sync.WaitGroup
	var bound binding
	defer func() {
		f.listening.Store(false)
		bound.close()
		f.conns.Range(func(conn, _ any) bool {
			if closer, ok := conn.(net.Conn); ok {
				_ = closer.Close()
			}
			return true
		})
		handlers.Wait()
	}()
	retry := listenRetryFirst
	rebind := true
	for {
		current, ok := f.Stacks.Current()
		if rebind || !ok || current.Retired != bound.retired {
			f.listening.Store(false)
			bound.close()
			bound = binding{}
			if ok {
				bound = f.bind(ctx, current, &handlers)
			}
			complete := ok && len(bound.listeners) == len(current.Addresses)
			f.listening.Store(complete && len(bound.listeners) > 0)
			if complete {
				retry = listenRetryFirst
			} else if ok {
				bound.again = time.After(retry)
				retry = min(2*retry, listenRetryMax)
			}
		}
		rebind = false
		select {
		case <-ctx.Done():
			return nil
		case <-f.Stacks.Changes():
		case <-bound.retired:
		case <-bound.again:
			rebind = true
		}
	}
}

// binding is the forwarder's listeners on one stack.
type binding struct {
	listeners []*listener
	retired   <-chan struct{}
	again     <-chan time.Time
}

func (b binding) close() {
	for _, bound := range b.listeners {
		bound.close()
	}
}

// bind listens on the stack's addresses and starts accepting.
func (f *KubeAPIForwarder) bind(ctx context.Context, current Stack, handlers *sync.WaitGroup) binding {
	bound := binding{retired: current.Retired}
	for _, address := range current.Addresses {
		listened, err := current.Net.ListenTCPAddrPort(netip.AddrPortFrom(address, f.Port))
		if err != nil {
			f.Logger.Error("kube API listener failed", "address", address, "port", f.Port, "error", err)
			continue
		}
		f.Logger.Info("kube API listening", "address", address, "port", f.Port)
		bound.listeners = append(bound.listeners, &listener{Listener: listened})
	}
	for _, accepting := range bound.listeners {
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			f.accept(ctx, accepting, handlers)
		}()
	}
	return bound
}

func (f *KubeAPIForwarder) accept(ctx context.Context, bound *listener, handlers *sync.WaitGroup) {
	for {
		conn, err := bound.Accept()
		if err != nil {
			if bound.closed.Load() || ctx.Err() != nil {
				return
			}
			f.Logger.Warn("kube API accept failed", "error", err)
			time.Sleep(acceptRetry)
			continue
		}
		// Read once: gonet forgets the address once the peer resets.
		source := conn.RemoteAddr()
		if f.open.Add(1) > int64(f.MaxConnections) {
			f.open.Add(-1)
			f.Logger.Warn("kube API connection refused: too many open", "source", addressText(source),
				"limit", f.MaxConnections)
			_ = conn.Close()
			continue
		}
		f.conns.Store(conn, struct{}{})
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer f.open.Add(-1)
			defer f.conns.Delete(conn)
			f.forward(ctx, conn, source)
		}()
	}
}

// forward carries one kubectl connection from source to the API server and
// back.
func (f *KubeAPIForwarder) forward(ctx context.Context, client net.Conn, source net.Addr) {
	defer func() { _ = client.Close() }()
	deviceID, deviceName := f.device(source)
	log := f.Logger.With("source", addressText(source), "device_id", deviceID, "device_name", deviceName)

	dial, cancel := context.WithTimeout(ctx, kubeAPIDialTimeout)
	server, err := (&net.Dialer{}).DialContext(dial, "tcp", f.Backend)
	cancel()
	if err != nil {
		log.Warn("kube API server unreachable", "backend", f.Backend, "error", err)
		return
	}
	f.conns.Store(server, struct{}{})
	defer f.conns.Delete(server)
	defer func() { _ = server.Close() }()
	f.total.Add(1)
	log.Info("kube API connection opened")

	started := time.Now()
	var toAPI, fromAPI int64
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		toAPI = pipe(server, client, log)
	}()
	go func() {
		defer copies.Done()
		fromAPI = pipe(client, server, log)
	}()
	copies.Wait()
	log.Info("kube API connection closed", "bytes_to_api", toAPI, "bytes_from_api", fromAPI,
		"duration", time.Since(started).Round(time.Millisecond).String())
}

// pipe copies from src to dst until src ends. A clean end half-closes dst,
// so the other side sees it, and gives the other direction, which reads dst,
// halfClosedTimeout to finish. An error, or a side that cannot half-close,
// ends the whole connection.
func pipe(dst, src net.Conn, log *slog.Logger) int64 {
	written, err := io.Copy(dst, src)
	if err == nil {
		if half, ok := dst.(interface{ CloseWrite() error }); ok && half.CloseWrite() == nil {
			_ = dst.SetReadDeadline(time.Now().Add(halfClosedTimeout))
			return written
		}
	} else {
		log.Debug("kube API connection ended", "error", err)
	}
	_ = dst.Close()
	_ = src.Close()
	return written
}

// addressText is address as text, or empty for a connection whose address
// is gone.
func addressText(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}

// device names the map's Device at address, or nothing if the map has none
// there: the packet filter admits only map peers, so that is not expected.
func (f *KubeAPIForwarder) device(address net.Addr) (id, name string) {
	tcp, ok := address.(*net.TCPAddr)
	if !ok || f.PeerAt == nil {
		return "", ""
	}
	source, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return "", ""
	}
	peer, ok := f.PeerAt(source.Unmap())
	if !ok {
		return "", ""
	}
	return peer.DeviceID, peer.Name
}
