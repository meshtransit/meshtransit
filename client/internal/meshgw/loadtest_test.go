//go:build loadtest

package meshgw

// The load test (K1b design §8, §1 criterion 8; b7b): many Devices, each
// through its own userspace stack routed to the gateway's own, open
// watches they never read, uploads that stall and execs that stop reading,
// against an API server that keeps sending. The replica's live heap must
// stay within what §8 budgets for what it holds, and the limits must
// refuse what is past them. Run:
//
//	go test -tags loadtest -run TestLoad -v -timeout 10m ./internal/meshgw

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubeaudit"
	"meshtransit.net/client/internal/kubeproxy"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/rbaccheck"
)

const loadCluster = "load.kube.test"

// loadCertificate is a self-signed certificate for loadCluster.
func loadCertificate(t *testing.T) (*tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: loadCluster},
		DNSNames: []string{loadCluster}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// floodBackend is an API server, speaking HTTP/2 as a real one does, that
// sends watch events and exec output as a busy one would, and reads
// uploads slowly.
func floodBackend(t *testing.T) (string, string, func()) {
	t.Helper()
	event := []byte(`{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"` + strings.Repeat("p", 900) + `"}}}` + "\n")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Upgrade") != "":
			conn, buffered, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: SPDY/3.1\r\nConnection: Upgrade\r\n\r\n")
			_ = buffered.Flush()
			for {
				if _, err := conn.Write(event); err != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
		case r.Method == http.MethodPost:
			chunk := make([]byte, 1024)
			for {
				if _, err := r.Body.Read(chunk); err != nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
			for {
				if _, err := w.Write(event); err != nil {
					return
				}
				http.NewResponseController(w).Flush()
				if r.Context().Err() != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
	}))
	server.EnableHTTP2 = true // the gateway's HTTP/2 transport and its windows (review b7b H2)
	server.StartTLS()
	t.Cleanup(server.Close)
	closeAll := func() {
		server.CloseClientConnections()
		server.Close()
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		0o600); err != nil {
		t.Fatal(err)
	}
	return server.URL, ca, closeAll
}

type loadTokens struct{}

func (loadTokens) For(context.Context, string, string, string) (kubeproxy.Bearer, error) {
	return loadBearer{}, nil
}
func (loadTokens) Forget(string, string, string, kubeproxy.Bearer) {}

type loadBearer struct{}

func (loadBearer) Value() string { return "token" }
func (loadBearer) ID() []byte    { return []byte{1} }

type loadRecords struct{}

func (loadRecords) Record(context.Context, string, controlplane.KubeAuditIntent) kubeaudit.Answer {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return kubeaudit.Answer{Recorded: true, AuditID: id}
}
func (loadRecords) Finished([16]byte, int, time.Duration) {}
func (loadRecords) Denied(string, string)                 {}

// liveHeap is the live heap after collections (two empty sync.Pools).
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}

// stalled is an upload body that sends a little, then nothing until done.
type stalled struct {
	sent int
	done <-chan struct{}
}

func (body *stalled) Read(buffer []byte) (int, error) {
	if body.sent < 200_000 {
		n := min(len(buffer), 200_000-body.sent)
		body.sent += n
		return n, nil
	}
	<-body.done
	return 0, io.EOF
}

// The load test runs in two processes, so the gateway's heap is its own
// (review b7b H2): this one holds the gateway (its stack and proxy);
// TestLoadHarness, run as a child, holds the Devices' stacks, their clients
// and the API server. Packets cross between them on unix datagram sockets,
// as the data plane carries them; the two speak a line protocol on the
// child's stdin and stdout.
const (
	loadDevices, loadH2Connections, loadStreamsPerConnection, loadExecs = 24, 4, 40, 4
	loadSoftLimit                                                       = 912680550 // a 1 GiB pod
)

var loadGatewayAddress = netip.MustParseAddr("100.64.0.1")

func loadDeviceAddress(index int) netip.Addr {
	return netip.AddrFrom4([4]byte{100, 64, 1, byte(index + 1)})
}

// packetPipe moves a stack's packets to a unix datagram socket and back.
func packetPipe(stack *meshStack, conn *net.UnixConn, peer *net.UnixAddr, deliver func([]byte)) {
	go func() {
		buffer := make([]byte, netstackMTU)
		sizes := []int{0}
		for {
			if _, err := stack.Read([][]byte{buffer}, sizes, 0); err != nil {
				return
			}
			_, _ = conn.WriteToUnix(buffer[:sizes[0]], peer)
		}
	}()
	go func() {
		buffer := make([]byte, netstackMTU+64)
		for {
			n, _, err := conn.ReadFromUnix(buffer)
			if err != nil {
				return
			}
			deliver(buffer[:n])
		}
	}()
}

func unixDatagram(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadBuffer(8 << 20)
	_ = conn.SetWriteBuffer(8 << 20)
	return conn
}

// TestLoad: Devices each hold HTTP/2 connections carrying watches they
// never read and uploads that stall, and HTTP/1.1 execs they stop reading,
// past the replica's streams, so its limits refuse the rest. Under load the
// gateway's live heap must fit §8's budget for what it holds; once every
// client is gone, with the gateway and the API server still running, it must
// come back (review b7b H2, M1).
func TestLoad(t *testing.T) {
	if os.Getenv("LOADTEST_HARNESS") != "" {
		t.Skip("the harness's process")
	}
	dir, err := os.MkdirTemp("", "mtload")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	gatewaySocket, harnessSocket := filepath.Join(dir, "gw"), filepath.Join(dir, "devices")
	gateway, err := newMeshStack([]netip.Addr{loadGatewayAddress}, netstackMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	socket := unixDatagram(t, gatewaySocket)
	defer socket.Close()
	packetPipe(gateway, socket, &net.UnixAddr{Name: harnessSocket, Net: "unixgram"},
		func(packet []byte) { _, _ = gateway.Write([][]byte{packet}, 0) })

	certificate, _ := loadCertificate(t)
	certificateFile := filepath.Join(dir, "gateway.crt")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Leaf.Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run", "^TestLoadHarness$", "-test.v", "-test.timeout", "15m")
	child.Env = append(os.Environ(), "LOADTEST_HARNESS=1", "LOADTEST_GATEWAY="+gatewaySocket,
		"LOADTEST_DEVICES="+harnessSocket, "LOADTEST_CERTIFICATE="+certificateFile)
	child.Stderr = os.Stderr
	stdin, _ := child.StdinPipe()
	stdout, _ := child.StdoutPipe()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	lines := bufio.NewScanner(stdout)
	expect := func(prefix string) string {
		t.Helper()
		for lines.Scan() {
			if line := lines.Text(); strings.HasPrefix(line, prefix) {
				return strings.TrimPrefix(line, prefix)
			}
		}
		t.Fatalf("the harness ended before %q", prefix)
		return ""
	}
	backend, ca, _ := strings.Cut(expect("BACKEND "), " ")

	counter := &countingHandler{counts: map[string]int{}}
	keys := map[netip.Addr][32]byte{}
	for index := range loadDevices {
		keys[loadDeviceAddress(index)] = [32]byte{byte(index + 1)}
	}
	// LOADTEST_SOFT_LIMIT sizes a smaller pod, so its watermark refuses
	// (memory pressure, §8).
	softLimit := int64(loadSoftLimit)
	if raw := os.Getenv("LOADTEST_SOFT_LIMIT"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			softLimit = parsed
		}
	}
	limits := limitsFor(softLimit)
	memory := newMemoryWatch(softLimit)
	proxy, err := kubeproxy.New(kubeproxy.Options{
		Cluster: "load", Namespace: "mt", Groups: []kubeproxy.Group{{Name: "edit", Default: true}},
		Backend: backend, BackendCA: ca,
		Peer: func(source netip.Addr) (kubeproxy.Peer, bool) {
			key, ok := keys[source]
			return kubeproxy.Peer{
				DeviceID: "device-" + source.String(), Name: source.String(), Key: key,
				Access: &networkmap.KubernetesAccess{
					OwnerRef: "person",
					Grants:   []networkmap.KubernetesGrant{{Group: "edit", ValidUntil: time.Now().Add(time.Hour)}},
				},
			}, ok
		},
		Certificate: func() (*tls.Certificate, bool) { return certificate, true },
		MapFreshAt:  time.Now, StaleAfter: 5 * time.Minute, CoreNow: time.Now,
		Verdict: func(string) rbaccheck.Verdict { return rbaccheck.Verdict{Enabled: true} },
		Records: loadRecords{}, Tokens: loadTokens{}, Limits: limits, Pressure: memory.Pressure,
		Version: "load", Logger: slog.New(counter),
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := gateway.ListenTCPAddrPort(netip.AddrPortFrom(loadGatewayAddress, 443))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = proxy.Serve(ctx, listener) }()
	go func() { _ = proxy.Run(ctx) }()
	go func() { _ = memory.Run(ctx) }()

	before := liveHeap()
	baseGoroutines := runtime.NumGoroutine()
	_, _ = io.WriteString(stdin, "start\n")
	t.Logf("harness: %s", expect("HELD "))
	held := liveHeap()
	sessions, connections := proxy.Sessions(), proxy.Connections()
	open := 0
	for _, count := range sessions.Open {
		open += count
	}
	budget := uint64(connections.Open)*connectionMemory + uint64(open)*streamMemory
	t.Logf("gateway: connections %+v, sessions %v (%d)", connections, sessions.Open, open)
	t.Logf("limited %v; memory pressure %t", proxy.Limited(), memory.Pressure())
	t.Logf("gateway live heap %d MiB before, %d MiB under load, budget for what it holds %d MiB; goroutines %d",
		before>>20, held>>20, budget>>20, runtime.NumGoroutine())
	if held > before && held-before > budget {
		t.Errorf("held %d MiB past the budget of %d MiB", (held-before)>>20, budget>>20)
	}
	if held > uint64(softLimit) {
		t.Errorf("held %d MiB past the soft limit of %d MiB", held>>20, softLimit>>20)
	}
	if open > limits.Streams || connections.MostByDevice > limits.DeviceConnections {
		t.Errorf("past the limits: %d sessions of %d, %d connections for a Device", open, limits.Streams,
			connections.MostByDevice)
	}
	if limited := proxy.Limited(); limited["streams"]+limited["fair_share"] == 0 {
		t.Errorf("nothing refused past the replica's streams: %v", limited)
	}

	// The clients go; the gateway and the API server stay.
	_, _ = io.WriteString(stdin, "release\n")
	expect("RELEASED")
	deadline := time.Now().Add(90 * time.Second)
	for {
		sessions, connections = proxy.Sessions(), proxy.Connections()
		open = 0
		for _, count := range sessions.Open {
			open += count
		}
		if connections.Open == 0 && open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still held after every client left: connections %+v, sessions %v", connections, sessions.Open)
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(5 * time.Second)
	after := liveHeap()
	t.Logf("every client gone, gateway running: live heap %d MiB, goroutines %d (base %d)", after>>20,
		runtime.NumGoroutine(), baseGoroutines)
	if after > before+16<<20 {
		t.Errorf("held %d MiB after every client left", (after-before)>>20)
	}
	if extra := runtime.NumGoroutine() - baseGoroutines; extra > 64 {
		buffer := make([]byte, 1<<20)
		t.Errorf("%d goroutines more than before; by function:\n%s", extra,
			summarizeGoroutines(string(buffer[:runtime.Stack(buffer, true)])))
	}
	_, _ = io.WriteString(stdin, "exit\n")
}

// TestLoadHarness is the load test's other process: the Devices and the
// API server.
func TestLoadHarness(t *testing.T) {
	if os.Getenv("LOADTEST_HARNESS") == "" {
		t.Skip("run by TestLoad")
	}
	backend, ca, closeBackend := floodBackend(t)
	defer closeBackend()
	socket := unixDatagram(t, os.Getenv("LOADTEST_DEVICES"))
	defer socket.Close()
	gatewayPeer := &net.UnixAddr{Name: os.Getenv("LOADTEST_GATEWAY"), Net: "unixgram"}
	trusted, err := os.ReadFile(os.Getenv("LOADTEST_CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(trusted)
	devices := map[netip.Addr]*meshStack{}
	var mu sync.Mutex
	go func() {
		buffer := make([]byte, netstackMTU+64)
		for {
			n, _, err := socket.ReadFromUnix(buffer)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			mu.Lock()
			target := devices[netip.AddrFrom4([4]byte(buffer[16:20]))]
			mu.Unlock()
			if target != nil {
				_, _ = target.Write([][]byte{buffer[:n]}, 0)
			}
		}
	}()
	for index := range loadDevices {
		address := loadDeviceAddress(index)
		stack, err := newMeshStack([]netip.Addr{address}, netstackMTU)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		devices[address] = stack
		mu.Unlock()
		go func() {
			buffer := make([]byte, netstackMTU)
			sizes := []int{0}
			for {
				if _, err := stack.Read([][]byte{buffer}, sizes, 0); err != nil {
					return
				}
				_, _ = socket.WriteToUnix(buffer[:sizes[0]], gatewayPeer)
			}
		}()
	}
	fmt.Printf("BACKEND %s %s\n", backend, ca)
	commands := bufio.NewScanner(os.Stdin)
	next := func() string {
		if !commands.Scan() {
			return "exit"
		}
		return commands.Text()
	}
	if next() != "start" {
		return
	}
	clients, stopClients := context.WithCancel(context.Background())
	var raw sync.Map
	var answered, failed atomic.Int64
	var wait sync.WaitGroup
	for index := range loadDevices {
		stack := devices[loadDeviceAddress(index)]
		wait.Go(func() {
			dial := func(protocol string) (net.Conn, error) {
				time.Sleep(110 * time.Millisecond) // under 10 handshakes a second
				conn, err := loadDial(clients, stack, loadGatewayAddress, pool, protocol)
				if err == nil {
					raw.Store(conn, struct{}{})
				}
				return conn, err
			}
			for range loadH2Connections {
				conn, err := dial("h2")
				if err != nil {
					failed.Add(1)
					continue
				}
				// Small client windows: the harness's buffers are not the
				// gateway's anyway, but they need not be large.
				transport := &http.Transport{
					ForceAttemptHTTP2: true,
					DialTLSContext:    func(context.Context, string, string) (net.Conn, error) { return conn, nil },
					HTTP2:             &http.HTTP2Config{MaxReceiveBufferPerStream: 64 << 10, MaxReceiveBufferPerConnection: 1 << 20},
				}
				client := &http.Client{Transport: transport}
				for stream := range loadStreamsPerConnection {
					go func() {
						// Spread under the Device's 50 requests a second.
						time.Sleep(time.Duration(stream) * 120 * time.Millisecond)
						var request *http.Request
						if stream%5 == 4 {
							request, _ = http.NewRequestWithContext(clients, http.MethodPost,
								"https://"+loadCluster+"/api/v1/namespaces/a/configmaps", &stalled{done: clients.Done()})
							request.Header.Set("Content-Type", "application/json")
						} else {
							request, _ = http.NewRequestWithContext(clients, http.MethodGet,
								"https://"+loadCluster+"/api/v1/pods?watch=true&sendInitialEvents=true", nil)
						}
						response, err := client.Do(request)
						if err != nil {
							failed.Add(1)
							return
						}
						answered.Add(1)
						<-clients.Done() // never read
						_ = response.Body.Close()
					}()
				}
			}
			for range loadExecs {
				conn, err := dial("http/1.1")
				if err != nil {
					failed.Add(1)
					continue
				}
				go func() {
					_, _ = io.WriteString(conn, "POST /api/v1/namespaces/a/pods/p/exec?command=sh HTTP/1.1\r\nHost: "+
						loadCluster+"\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
				}()
			}
		})
	}
	wait.Wait()
	time.Sleep(15 * time.Second) // windows and buffers fill
	fmt.Printf("HELD answered %d, failed %d\n", answered.Load(), failed.Load())
	if next() != "release" {
		stopClients()
		return
	}
	stopClients()
	raw.Range(func(conn, _ any) bool {
		if held, ok := conn.(net.Conn); ok {
			_ = held.Close()
		}
		return true
	})
	fmt.Println("RELEASED")
	next() // exit: the API server stays until then
}

// loadDial opens a TLS connection from a Device's stack to the gateway.
func loadDial(ctx context.Context, stack *meshStack, gateway netip.Addr, pool *x509.CertPool, protocol string,
) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := gonet.DialContextTCP(dialCtx, stack.stack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4(gateway.As4()), Port: 443,
	}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: loadCluster, NextProtos: []string{protocol}})
	if err := conn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return conn, nil
}

// countingHandler counts log lines by message and status.
type countingHandler struct {
	mu     sync.Mutex
	counts map[string]int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *countingHandler) WithGroup(string) slog.Handler            { return h }
func (h *countingHandler) Handle(_ context.Context, record slog.Record) error {
	key := record.Message
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "status" || attr.Key == "class" || attr.Key == "error" {
			key += " " + attr.Key + "=" + attr.Value.String()
		}
		return true
	})
	h.mu.Lock()
	h.counts[key]++
	h.mu.Unlock()
	return nil
}

func (h *countingHandler) snapshot() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	copied := map[string]int{}
	for key, count := range h.counts {
		copied[key] = count
	}
	return copied
}

// delayedPump moves packets from one stack to another after a one-way
// delay, as a mesh path does.
func delayedPump(from, to *meshStack, delay time.Duration) {
	type queued struct {
		packet []byte
		due    time.Time
	}
	// In order, as one path delivers them.
	queue := make(chan queued, 1<<16)
	go func() {
		for item := range queue {
			time.Sleep(time.Until(item.due))
			_, _ = to.Write([][]byte{item.packet}, 0)
		}
	}()
	buffer := make([]byte, netstackMTU)
	sizes := []int{0}
	for {
		if _, err := from.Read([][]byte{buffer}, sizes, 0); err != nil {
			close(queue)
			return
		}
		queue <- queued{packet: append([]byte(nil), buffer[:sizes[0]]...), due: time.Now().Add(delay)}
	}
}

// TestThroughput measures one download through the gateway over a path
// of a given round trip: the gateway's 96 KiB send buffer bounds it to
// about that much a round trip (review TD-CLI-82 M2).
func TestThroughput(t *testing.T) {
	const size = 8 << 20
	body := make([]byte, size)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		0o600); err != nil {
		t.Fatal(err)
	}
	certificate, pool := loadCertificate(t)
	for _, rtt := range []time.Duration{
		10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond,
		200 * time.Millisecond,
	} {
		gatewayAddress, deviceAddress := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.1.1")
		gateway, _ := newMeshStack([]netip.Addr{gatewayAddress}, netstackMTU)
		device, _ := newMeshStack([]netip.Addr{deviceAddress}, netstackMTU)
		go delayedPump(gateway, device, rtt/2)
		go delayedPump(device, gateway, rtt/2)
		proxy, err := kubeproxy.New(kubeproxy.Options{
			Cluster: "load", Namespace: "mt", Groups: []kubeproxy.Group{{Name: "edit", Default: true}},
			Backend: server.URL, BackendCA: ca,
			Peer: func(netip.Addr) (kubeproxy.Peer, bool) {
				return kubeproxy.Peer{DeviceID: "device", Key: [32]byte{1}, Access: &networkmap.KubernetesAccess{
					OwnerRef: "person", Grants: []networkmap.KubernetesGrant{{
						Group:      "edit",
						ValidUntil: time.Now().Add(time.Hour),
					}},
				}}, true
			},
			Certificate: func() (*tls.Certificate, bool) { return certificate, true },
			MapFreshAt:  time.Now, StaleAfter: 5 * time.Minute, CoreNow: time.Now,
			Verdict: func(string) rbaccheck.Verdict { return rbaccheck.Verdict{Enabled: true} },
			Records: loadRecords{}, Tokens: loadTokens{}, Version: "load", Logger: slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatal(err)
		}
		listener, _ := gateway.ListenTCPAddrPort(netip.AddrPortFrom(gatewayAddress, 443))
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = proxy.Serve(ctx, listener) }()
		conn, err := loadDial(ctx, device, gatewayAddress, pool, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_, _ = io.WriteString(conn, "GET /api/v1/namespaces/a/configmaps/big HTTP/1.1\r\nHost: "+loadCluster+"\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		read, err := io.Copy(io.Discard, response.Body)
		took := time.Since(started)
		if err != nil || response.StatusCode != http.StatusOK || read != size {
			t.Fatalf("RTT %s: status %d, %d of %d bytes, %v", rtt, response.StatusCode, read, size, err)
		}
		t.Logf("RTT %s: %d MiB in %s, %.2f MiB/s", rtt, read>>20, took.Round(time.Millisecond),
			float64(read)/float64(1<<20)/took.Seconds())
		_ = conn.Close()
		cancel()
		_ = gateway.Close()
		_ = device.Close()
	}
}

// summarizeGoroutines counts goroutines by their top frame.
func summarizeGoroutines(dump string) string {
	counts := map[string]int{}
	for _, block := range strings.Split(dump, "\n\n") {
		lines := strings.Split(block, "\n")
		if len(lines) > 1 {
			counts[strings.TrimSpace(lines[1])]++
		}
	}
	var out strings.Builder
	for frame, count := range counts {
		if count > 4 {
			fmt.Fprintf(&out, "%5d %s\n", count, frame)
		}
	}
	return out.String()
}
