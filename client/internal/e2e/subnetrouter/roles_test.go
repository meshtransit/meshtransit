//go:build e2e && linux

package subnetrouter

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/socket"
)

// A test binary started with envRole set plays that role in its namespace
// instead of running tests.
const (
	envRole = "MESHTRANSIT_E2E_ROLE"
	envNode = "MESHTRANSIT_E2E_NODE"
	envDir  = "MESHTRANSIT_E2E_DIR"
	// envScenario is "exit" for the exit node scenario and "spread" for the
	// spread Exit Pool one.
	envScenario = "MESHTRANSIT_E2E_SCENARIO"
	// Ports of the LAN host: who reached it, a byte sink and an echo.
	whoPort, sinkPort, echoPort = 7000, 7001, 7002
	routedTable, routedPriority = 5267, 5400
	exitTable, exitPriority     = 5268, 5402
)

func runRole(role string) int {
	var err error
	switch role {
	case "node":
		err = runNode(os.Getenv(envNode), os.Getenv(envDir))
	case "lan":
		err = runLAN()
	case "net":
		err = runNet()
	case "listen":
		err = runListen()
	case "dialconsumer":
		err = runWhoAt(nodes[consumer].underlay)
	case "whonet":
		if err = dropToNobody(); err == nil {
			err = runWhoAt(netHost)
		}
	case "who":
		if err = dropToNobody(); err == nil {
			err = runWho()
		}
	case "bench":
		if err = dropToNobody(); err == nil {
			err = runBench()
		}
	default:
		err = fmt.Errorf("unknown role %q", role)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, role+":", err)
		return 1
	}
	return 0
}

// runNode runs the helper and the data plane of one node, applying its map
// for the primary named in dir/<node>.primary whenever that file changes,
// and records each applied primary in dir/<node>.applied.
func runNode(name, dir string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	// Shown only when a test fails.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	settings := filepath.Join(dir, name+".routes.json")
	scenario := os.Getenv(envScenario)
	exitScenario := scenario == "exit" || scenario == "spread"
	local := routesettings.Settings{AcceptRoutes: true}
	switch {
	case exitScenario && (name == consumer || name == consumer2):
		local = routesettings.Settings{ExitUse: poolRef}
	case exitScenario:
		local = routesettings.Settings{ExitMode: true}
	case name != consumer:
		local = routesettings.Settings{RouterMode: true, AdvertiseRoutes: []netip.Prefix{sitePrefix}}
	}
	maps := mapFor
	switch scenario {
	case "exit":
		maps = exitMapFor
	case "spread":
		maps = spreadMapFor
	}
	if err := routesettings.Save(settings, local); err != nil {
		return fmt.Errorf("writing route settings: %w", err)
	}
	server, err := netadmin.NewServer(netadmin.ServerOptions{
		AllowedUID: uint32(os.Getuid()), InterfaceName: "mesh0", MTU: 1280, //nolint:gosec // a uid fits in uint32
		AllowedPrefixes: netadmin.SafeOverlayFrame(),
		Routed: &netadmin.RoutedOptions{
			SettingsPath: settings, Table: routedTable, Priority: routedPriority,
			NftTable: "meshtransit", StatePath: filepath.Join(dir, name+".router-state.json"),
			ExitTable: exitTable, ExitPriority: exitPriority, ExitNftTable: "meshtransit_exit",
		},
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("creating helper: %w", err)
	}
	socketPath := filepath.Join(dir, name+".netd.sock")
	listener, err := socket.ListenPacket(socketPath)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()
	client, err := netadmin.NewClient(socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to the helper: %w", err)
	}
	engine, err := dataplane.NewWireGuard(client, wireGuardPort)
	if err != nil {
		return fmt.Errorf("creating the data plane: %w", err)
	}
	engine.SetLogger(logger)
	applied, revision := "", uint64(0)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		wanted, err := os.ReadFile(filepath.Join(dir, name+".primary")) //nolint:gosec // the test's own directory
		if err == nil && strings.TrimSpace(string(wanted)) != "" && strings.TrimSpace(string(wanted)) != applied {
			primary := strings.TrimSpace(string(wanted))
			revision++
			if _, err := engine.Apply(ctx, maps(name, primary, revision), privateKey(name)); err != nil {
				return fmt.Errorf("applying the map for %s: %w", primary, err)
			}
			applied = primary
			if err := writeAtomically(filepath.Join(dir, name+".applied"), primary); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			// The data plane first, while the helper can still undo what
			// it installed for it.
			_ = engine.Close()
			_ = listener.Close()
			return nil
		case err := <-served:
			_ = engine.Close()
			return fmt.Errorf("helper stopped: %w", err)
		case <-ticker.C:
		}
	}
}

// runNet serves the Internet host's who: the address that reached it (the
// exit node's egress address, through its masquerade).
func runNet() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(netHost.String(), strconv.Itoa(whoPort)))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		_, _ = io.WriteString(conn, host+"\n")
		_ = conn.Close()
	}
}

// runListen serves who on the consumer's own network address: a service
// of the host that others open connections to, as SSH on a server.
func runListen() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	address := net.JoinHostPort(nodes[consumer].underlay.String(), strconv.Itoa(whoPort))
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil
		}
		_, _ = io.WriteString(conn, "consumer\n")
		_ = conn.Close()
	}
}

// runLAN serves the LAN host: who answers with the address that reached it
// (the router's, through masquerade), sink counts bytes until EOF, echo
// echoes.
func runLAN() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	serve := func(port int, handle func(net.Conn)) error {
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(lanHost.String(), strconv.Itoa(port)))
		if err != nil {
			return err
		}
		go func() {
			<-ctx.Done()
			_ = listener.Close()
		}()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = conn.Close() }()
					handle(conn)
				}()
			}
		}()
		return nil
	}
	if err := serve(whoPort, func(conn net.Conn) {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		_, _ = io.WriteString(conn, host+"\n")
	}); err != nil {
		return err
	}
	if err := serve(sinkPort, func(conn net.Conn) {
		count, _ := io.Copy(io.Discard, conn)
		_, _ = io.WriteString(conn, strconv.FormatInt(count, 10)+"\n")
	}); err != nil {
		return err
	}
	if err := serve(echoPort, func(conn net.Conn) { _, _ = io.Copy(conn, conn) }); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// runWho prints the address the LAN host saw, or fails within 2 s.
func runWho() error { return runWhoAt(lanHost) }

// runWhoAt prints the address host's who service saw, or fails within 2 s.
func runWhoAt(host netip.Addr) error {
	conn, err := dialHost(host, whoPort)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

// Measurement is what runBench reports.
type Measurement struct {
	ThroughputMbps float64 `json:"throughput_mbps"`
	Bytes          int64   `json:"bytes"`
	Seconds        float64 `json:"seconds"`
	RoundTrips     int     `json:"round_trips"`
	LatencyP50Ms   float64 `json:"latency_p50_ms"`
	LatencyP99Ms   float64 `json:"latency_p99_ms"`
}

// runBench sends to the LAN host's sink for benchSeconds and times
// benchRoundTrips one-byte echoes, then prints the Measurement as JSON.
func runBench() error {
	const benchDuration, benchRoundTrips = 5 * time.Second, 500
	sink, err := dialLAN(sinkPort)
	if err != nil {
		return err
	}
	defer func() { _ = sink.Close() }()
	chunk := make([]byte, 64<<10)
	started := time.Now()
	var sent int64
	for time.Since(started) < benchDuration {
		written, err := sink.Write(chunk)
		sent += int64(written)
		if err != nil {
			return err
		}
	}
	if err := sink.CloseWrite(); err != nil {
		return err
	}
	line, err := bufio.NewReader(sink).ReadString('\n')
	if err != nil {
		return err
	}
	received, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
	if err != nil {
		return err
	}
	elapsed := time.Since(started).Seconds()
	if received != sent {
		return fmt.Errorf("sent %d bytes, the host received %d", sent, received)
	}
	echo, err := dialLAN(echoPort)
	if err != nil {
		return err
	}
	defer func() { _ = echo.Close() }()
	_ = echo.SetNoDelay(true)
	rtts := make([]float64, 0, benchRoundTrips)
	one := []byte{1}
	for range benchRoundTrips {
		start := time.Now()
		if _, err := echo.Write(one); err != nil {
			return err
		}
		if _, err := io.ReadFull(echo, one); err != nil {
			return err
		}
		rtts = append(rtts, float64(time.Since(start).Microseconds())/1000)
	}
	slices.Sort(rtts)
	measurement := Measurement{
		ThroughputMbps: float64(received) * 8 / elapsed / 1e6, Bytes: received, Seconds: elapsed,
		RoundTrips: len(rtts), LatencyP50Ms: rtts[len(rtts)/2], LatencyP99Ms: rtts[len(rtts)*99/100],
	}
	return json.NewEncoder(os.Stdout).Encode(measurement)
}

// dropToNobody makes a probe an ordinary user: the helper's routed table
// applies to every user but meshd's (here root), as on a host where meshd
// has a user of its own.
func dropToNobody() error {
	const nobody = 65534
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(nobody); err != nil {
		return err
	}
	return syscall.Setuid(nobody)
}

// dialLAN connects to the LAN host's port within 2 s.
func dialLAN(port int) (*net.TCPConn, error) { return dialHost(lanHost, port) }

// dialHost connects to host's port within 2 s.
func dialHost(host netip.Addr, port int) (*net.TCPConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host.String(), strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("not a TCP connection: %T", conn)
	}
	return tcp, nil
}

// writeAtomically replaces path with text, so a reader never sees it half
// written.
func writeAtomically(path, text string) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(text), 0o600); err != nil { //nolint:gosec // the test's own directory
		return err
	}
	return os.Rename(temporary, path) //nolint:gosec // the test's own directory
}
