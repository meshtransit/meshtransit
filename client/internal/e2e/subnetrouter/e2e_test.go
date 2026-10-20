//go:build e2e && linux

package subnetrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if role := os.Getenv(envRole); role != "" {
		os.Exit(runRole(role))
	}
	os.Exit(m.Run())
}

// lab is one topology: a hub namespace bridging an underlay (consumer and
// routers) and the Site's LAN (routers and the LAN host). The consumer has
// no route into the LAN but the mesh.
type lab struct {
	t        *testing.T
	suffix   string
	dir      string
	mu       sync.Mutex
	children map[string]*child
}

type child struct {
	cmd    *exec.Cmd
	output *lockedBuffer
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

// labs numbers the labs of one run, so each has namespaces of its own.
var labs atomic.Int64

// codes are the one-letter names of the namespaces, kept short so the
// namespace and interface names fit.
var codes = map[string]string{"hub": "h", consumer: "c", routerA: "a", routerB: "b", "lan": "l"}

func newLab(t *testing.T) *lab {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	suffix := strconv.Itoa(os.Getpid()%10000) + strconv.FormatInt(labs.Add(1), 36)
	l := &lab{t: t, suffix: suffix, dir: t.TempDir(), children: map[string]*child{}}
	t.Cleanup(l.close)
	for name := range codes {
		l.ip("netns", "add", l.ns(name))
		l.ip("-n", l.ns(name), "link", "set", "lo", "up")
		// The kernel checks a packet's reverse path as uid 0. Here meshd
		// runs as root, so its own policy rule (not uidrange 0-0) also
		// keeps those checks out of the routed table, and a host that sets
		// rp_filter (GitHub's runners do) drops every reply from the Site. A
		// real meshd runs as its own user and is not affected.
		l.ip("netns", "exec", l.ns(name), "sh", "-c",
			"echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter && echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter")
	}
	hub := l.ns("hub")
	for _, bridge := range []string{"bu", "bl"} {
		l.ip("-n", hub, "link", "add", bridge, "type", "bridge")
		l.ip("-n", hub, "link", "set", bridge, "up")
	}
	attach := func(name, inside, bridge, address string) {
		peer := "h" + codes[name] + bridge[1:]
		l.ip("link", "add", inside, "netns", l.ns(name), "type", "veth", "peer", "name", peer, "netns", hub)
		l.ip("-n", hub, "link", "set", peer, "master", bridge, "up")
		l.ip("-n", l.ns(name), "addr", "add", address, "dev", inside)
		l.ip("-n", l.ns(name), "link", "set", inside, "up")
	}
	for _, name := range []string{consumer, routerA, routerB} {
		attach(name, "under0", "bu", nodes[name].underlay.String()+"/24")
	}
	for _, name := range []string{routerA, routerB} {
		attach(name, "lan0", "bl", nodes[name].lan.String()+"/24")
	}
	attach("lan", "lan0", "bl", lanHost.String()+"/24")
	return l
}

func (l *lab) ns(name string) string { return "mtx" + l.suffix + codes[name] }

func (l *lab) ip(args ...string) {
	l.t.Helper()
	if output, err := exec.CommandContext(context.Background(), "ip", args...).CombinedOutput(); err != nil { //nolint:gosec // the test's own arguments
		l.t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, output)
	}
}

// start runs the test binary in name's namespace in role.
func (l *lab) start(name, role string) {
	l.t.Helper()
	self, err := os.Executable()
	if err != nil {
		l.t.Fatal(err)
	}
	// Not bound to a context: stop ends it, with the signal the test chose.
	cmd := exec.CommandContext(context.Background(), "ip", "netns", "exec", l.ns(name), self, //nolint:gosec // this test binary
		"-test.run=^$")
	cmd.Env = append(os.Environ(), envRole+"="+role, envNode+"="+name, envDir+"="+l.dir)
	output := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.mu.Lock()
	l.children[name] = &child{cmd: cmd, output: output}
	l.mu.Unlock()
}

// stop ends name's process: SIGKILL makes a router die without a word.
func (l *lab) stop(name string, signal syscall.Signal) {
	l.mu.Lock()
	running := l.children[name]
	delete(l.children, name)
	l.mu.Unlock()
	if running == nil {
		return
	}
	_ = running.cmd.Process.Signal(signal)
	done := make(chan struct{})
	go func() {
		_ = running.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = running.cmd.Process.Kill()
		<-done
	}
	if l.t.Failed() {
		l.t.Logf("%s output:\n%s", name, running.output.String())
	}
}

func (l *lab) close() {
	l.mu.Lock()
	names := make([]string, 0, len(l.children))
	for name := range l.children {
		names = append(names, name)
	}
	l.mu.Unlock()
	for _, name := range names {
		l.stop(name, syscall.SIGTERM)
	}
	for name := range codes {
		//nolint:gosec // the test's own namespaces
		if output, err := exec.CommandContext(context.Background(), "ip", "netns", "del", l.ns(name)).CombinedOutput(); err != nil {
			l.t.Logf("removing namespace %s: %v: %s", l.ns(name), err, output)
		}
	}
}

// route makes name apply its map for primary and waits until it did.
func (l *lab) route(name, primary string) {
	l.t.Helper()
	if err := writeAtomically(filepath.Join(l.dir, name+".primary"), primary); err != nil {
		l.t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		applied, err := os.ReadFile(filepath.Join(l.dir, name+".applied")) //nolint:gosec // the test's own directory
		if err == nil && string(applied) == primary {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	l.t.Fatalf("%s did not apply its map for %s", name, primary)
}

// run runs role once in the consumer's namespace and returns its output.
func (l *lab) run(role string, timeout time.Duration) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", l.ns(consumer), self, "-test.run=^$") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), envRole+"="+role, envDir+"="+l.dir)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	return strings.TrimSpace(output.String()), err
}

// waitThrough waits until the LAN host sees the consumer arrive from
// router's address in the Site (its masquerade) and returns how long it took.
func (l *lab) waitThrough(router string, timeout time.Duration) time.Duration {
	l.t.Helper()
	want := nodes[router].lan.String()
	started := time.Now()
	last := ""
	for time.Since(started) < timeout {
		seen, err := l.run("who", 3*time.Second)
		if err == nil && seen == want {
			return time.Since(started)
		}
		last = fmt.Sprintf("%q (%v)", seen, err)
		time.Sleep(100 * time.Millisecond)
	}
	l.dump()
	l.t.Fatalf("the LAN host never saw %s through %s; last %s", want, router, last)
	return 0
}

// dump logs each namespace's addresses, routes, rules, forwarding settings
// and nftables rules: what a failure on another kernel needs to be read.
func (l *lab) dump() {
	for _, name := range []string{consumer, routerA, routerB, "lan"} {
		for _, command := range [][]string{
			{"ip", "-br", "addr"},
			{"ip", "route", "show", "table", "all"},
			{"ip", "rule"},
			{"sh", "-c", "grep -H . /proc/sys/net/ipv4/conf/*/forwarding /proc/sys/net/ipv4/conf/*/rp_filter"},
			{"nft", "list", "ruleset"},
			{"ip", "-s", "link", "show", "dev", "mesh0"},
		} {
			args := append([]string{"netns", "exec", l.ns(name)}, command...)
			//nolint:gosec // the test's own namespaces and commands
			output, err := exec.CommandContext(context.Background(), "ip", args...).CombinedOutput()
			l.t.Logf("%s: %s (%v):\n%s", name, strings.Join(command, " "), err, output)
		}
	}
}

// up starts the LAN host, both routers and the consumer with primary.
func (l *lab) up(primary string) {
	l.t.Helper()
	l.start("lan", "lan")
	for _, name := range []string{routerA, routerB, consumer} {
		l.start(name, "node")
	}
	for _, name := range []string{routerA, routerB} {
		l.route(name, "serve")
	}
	// Before the consumer's map the LAN is out of its reach: nothing but the
	// mesh can carry the test's traffic.
	if seen, err := l.run("who", 5*time.Second); err == nil || !strings.Contains(seen, "network is unreachable") {
		l.t.Fatalf("the consumer reached the LAN without the mesh: %q, %v", seen, err)
	}
	l.route(consumer, primary)
}

// TestSubnetRouterE2E: the consumer reaches the Site's host through its
// primary router, and through the other router once the first one dies and
// the map names the other.
func TestSubnetRouterE2E(t *testing.T) {
	l := newLab(t)
	l.up(routerA)
	t.Logf("first packet through %s after %v", routerA, l.waitThrough(routerA, 30*time.Second))

	// Router A dies without a word; Core elects router B.
	l.stop(routerA, syscall.SIGKILL)
	started := time.Now()
	l.route(consumer, routerB)
	took := l.waitThrough(routerB, 20*time.Second)
	t.Logf("through %s %v after the new map (%v after %s died)", routerB, took, time.Since(started), routerA)

	// A Site no router serves is answered at once, never left to time out
	// or leak elsewhere (mtcp-v1 §7.6).
	l.route(consumer, unserved)
	started = time.Now()
	// The consumer's data plane answers ICMP host unreachable ("no route to
	// host"); without the mesh's route the kernel would say "network is
	// unreachable", which up checked before.
	if seen, err := l.run("who", 5*time.Second); err == nil || !strings.Contains(seen, "no route to host") {
		t.Fatalf("an unserved Site answered %q, %v", seen, err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("an unserved Site took %v to refuse", waited)
	}
	l.route(consumer, routerB)
	l.waitThrough(routerB, 20*time.Second)
}

// TestSubnetRouterBenchmark measures throughput and latency from the
// consumer to the Site's host through a router; MESHTRANSIT_E2E_BENCH names
// the JSON file the measurement goes to.
func TestSubnetRouterBenchmark(t *testing.T) {
	path := os.Getenv("MESHTRANSIT_E2E_BENCH")
	if path == "" {
		t.Skip("MESHTRANSIT_E2E_BENCH is not set")
	}
	l := newLab(t)
	l.up(routerA)
	l.waitThrough(routerA, 30*time.Second)
	output, err := l.run("bench", 60*time.Second)
	if err != nil {
		t.Fatalf("bench: %v: %s", err, output)
	}
	var measurement Measurement
	if err := json.Unmarshal([]byte(output), &measurement); err != nil {
		t.Fatalf("bench output %q: %v", output, err)
	}
	t.Logf("through %s: %.1f Mbit/s, latency p50 %.2f ms p99 %.2f ms", routerA, measurement.ThroughputMbps,
		measurement.LatencyP50Ms, measurement.LatencyP99Ms)
	if err := os.WriteFile(path, []byte(output+"\n"), 0o600); err != nil { //nolint:gosec // where the runner asked
		t.Fatal(err)
	}
	// Floors that only a broken path misses, whatever the CI machine.
	if measurement.ThroughputMbps < 5 || measurement.LatencyP99Ms > 100 {
		t.Fatalf("through the router: %+v", measurement)
	}
}
