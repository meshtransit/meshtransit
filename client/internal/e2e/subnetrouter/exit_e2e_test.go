//go:build e2e && linux

package subnetrouter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newExitLab builds the exit scenario: the consumer and two exit nodes on
// an underlay, the exit nodes' egress network routed by the hub to the
// Internet host, and a LAN behind exit A that no consumer may reach. The
// consumer's own network has a default route and a planted route to the
// Internet host (a rogue DHCP server's), and counts what leaves by it.
func newExitLab(t *testing.T) *lab {
	t.Helper()
	l := newEgressLab(t, "exit", consumer)
	l.attach(exitA, "lan0", "bl", "10.50.0.2/24")
	l.attach("lan", "lan0", "bl", lanHost.String()+"/24")
	return l
}

// newEgressLab builds the namespaces of scenario: consumers and two exit
// nodes on an underlay, the exit nodes' egress network routed by the hub to
// the Internet host, and each consumer's own network with a default route,
// a planted route to the Internet host, and a count of what leaves by it.
// The exit scenario also has the namespaces of a LAN behind exit A.
func newEgressLab(t *testing.T, scenario string, consumers ...string) *lab {
	t.Helper()
	names := append([]string{"hub"}, consumers...)
	names = append(names, exitA, exitB, "net")
	if scenario == "exit" {
		names = append(names, "lan")
	}
	l := newBareLab(t, names...)
	l.scenario = scenario
	hub := l.ns("hub")
	for _, bridge := range []string{"bu", "bx", "bi", "bl"} {
		l.ip("-n", hub, "link", "add", bridge, "type", "bridge")
		l.ip("-n", hub, "link", "set", bridge, "up")
	}
	l.ip("-n", hub, "addr", "add", egressGateway.String()+"/24", "dev", "bx")
	l.ip("-n", hub, "addr", "add", netGateway.String()+"/24", "dev", "bi")
	l.exec(hub, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	for _, name := range append([]string{exitA, exitB}, consumers...) {
		l.attach(name, "under0", "bu", nodes[name].underlay.String()+"/24")
	}
	for _, name := range []string{exitA, exitB} {
		l.attach(name, "egress0", "bx", nodes[name].lan.String()+"/24")
		l.ip("-n", l.ns(name), "route", "add", "default", "via", egressGateway.String())
	}
	l.attach("net", "net0", "bi", netHost.String()+"/24")
	l.ip("-n", l.ns("net"), "route", "add", "default", "via", netGateway.String())
	for _, name := range consumers {
		namespace := l.ns(name)
		l.ip("-n", namespace, "route", "add", "default", "via", "10.99.0.254")
		// Loose reverse path checks, as Ubuntu sets them.
		l.exec(namespace, "sh", "-c",
			"echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter && echo 2 > /proc/sys/net/ipv4/conf/under0/rp_filter")
		l.ip("-n", namespace, "route", "add", "34.10.0.0/24", "via", "10.99.0.254")
		l.exec(namespace, "nft", "add", "table", "inet", "leak")
		l.exec(namespace, "nft", "add", "chain", "inet", "leak", "out",
			"{ type filter hook output priority -300; }")
		l.exec(namespace, "nft", "add", "rule", "inet", "leak", "out",
			"oifname", "under0", "ip", "daddr", "34.10.0.0/24", "counter")
	}
	return l
}

func (l *lab) exec(namespace string, command ...string) {
	l.t.Helper()
	args := append([]string{"netns", "exec", namespace}, command...)
	//nolint:gosec // the test's own namespaces and commands
	if output, err := exec.CommandContext(context.Background(), "ip", args...).CombinedOutput(); err != nil {
		l.t.Fatalf("%s: %v: %s", strings.Join(command, " "), err, output)
	}
}

// leaked returns how many packets the consumer name sent to the Internet
// host by its own network.
func (l *lab) leaked(name string) string {
	l.t.Helper()
	//nolint:gosec // the test's own namespace
	output, err := exec.CommandContext(context.Background(), "ip", "netns", "exec", l.ns(name),
		"nft", "list", "chain", "inet", "leak", "out").CombinedOutput()
	if err != nil {
		l.t.Fatalf("reading the leak counter: %v: %s", err, output)
	}
	text := string(output)
	index := strings.Index(text, "counter packets ")
	if index < 0 {
		l.t.Fatalf("no leak counter:\n%s", text)
	}
	return strings.Fields(text[index+len("counter packets "):])[0]
}

// waitExit waits until the Internet host sees the consumer from arrive
// from exit's egress address.
func (l *lab) waitExit(from, exit string, timeout time.Duration) time.Duration {
	l.t.Helper()
	want := nodes[exit].lan.String()
	started := time.Now()
	last := ""
	for time.Since(started) < timeout {
		seen, err := l.runIn(from, "whonet", 3*time.Second)
		if err == nil && seen == want {
			return time.Since(started)
		}
		last = seen
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatalf("the Internet host never saw %s through %s; last %q", from, exit, last)
	return 0
}

// TestExitNodeE2E: the consumer reaches the Internet only through its exit
// node, never its LAN, moves to the other exit node when Core's choice
// changes, and sends nothing outside the mesh while no exit node carries
// its traffic, a planted route notwithstanding (exit node design §12).
func TestExitNodeE2E(t *testing.T) {
	l := newExitLab(t)
	l.start("net", "net")
	l.start("lan", "lan")
	for _, name := range []string{exitA, exitB, consumer} {
		l.start(name, "node")
	}
	for _, name := range []string{exitA, exitB} {
		l.route(name, "serve")
	}
	l.startIn(consumer, consumer+"-listen", "listen")
	l.route(consumer, exitA)
	t.Logf("through %s after %v", exitA, l.waitExit(consumer, exitA, 30*time.Second))
	// Connections opened from outside keep working, as SSH to a server.
	if seen, err := l.runIn(exitB, "dialconsumer", 5*time.Second); err != nil || seen != "consumer" {
		t.Fatalf("a connection from outside failed while using an exit node: %q, %v", seen, err)
	}

	// The exit node's LAN is no Internet.
	if seen, err := l.run("who", 5*time.Second); err == nil {
		t.Fatalf("the consumer reached the exit node's LAN: %q", seen)
	}

	l.stop(exitA, syscall.SIGKILL)
	l.route(consumer, exitB)
	t.Logf("through %s %v after the new choice", exitB, l.waitExit(consumer, exitB, 20*time.Second))

	// No exit node: the Internet is unreachable, and nothing leaves by the
	// consumer's own network.
	l.route(consumer, none)
	if seen, err := l.run("whonet", 5*time.Second); err == nil {
		t.Fatalf("the Internet answered without an exit node: %q", seen)
	}
	if leaked := l.leaked(consumer); leaked != "0" {
		t.Fatalf("%s packets left by the consumer's own network", leaked)
	}
	l.route(consumer, exitB)
	l.waitExit(consumer, exitB, 20*time.Second)

	// meshd dies: its TUN goes, the kill switch stays. Nothing leaves for
	// the Internet, and the host is still reachable from outside.
	l.stop(consumer, syscall.SIGKILL)
	if seen, err := l.run("whonet", 5*time.Second); err == nil {
		t.Fatalf("the Internet answered after meshd died: %q", seen)
	}
	if leaked := l.leaked(consumer); leaked != "0" {
		t.Fatalf("%s packets left by the consumer's own network after meshd died", leaked)
	}
	if seen, err := l.runIn(exitB, "dialconsumer", 5*time.Second); err != nil || seen != "consumer" {
		t.Fatalf("the host became unreachable after meshd died: %q, %v", seen, err)
	}
}

// TestExitPoolSpreadE2E: a spread pool's consumers use exit nodes of their
// own at once. When one exit node dies its consumer moves to the other,
// which then carries both, and moves back once it returns; the other
// consumer's exit node never changes, and nothing leaves by either
// consumer's own network (exit node design §16).
func TestExitPoolSpreadE2E(t *testing.T) {
	l := newEgressLab(t, "spread", consumer, consumer2)
	l.start("net", "net")
	for _, name := range []string{exitA, exitB, consumer, consumer2} {
		l.start(name, "node")
	}
	for _, name := range []string{exitA, exitB} {
		l.route(name, "serve")
	}
	for _, name := range []string{consumer, consumer2} {
		l.route(name, spreadPrimaries[name])
	}
	for _, name := range []string{consumer, consumer2} {
		t.Logf("%s through %s after %v", name, spreadPrimaries[name],
			l.waitExit(name, spreadPrimaries[name], 30*time.Second))
	}

	// Exit A dies: until the consumer moves, its Internet is unreachable
	// and nothing leaks; consumer 2 keeps exit B.
	l.stop(exitA, syscall.SIGKILL)
	if seen, err := l.run("whonet", 5*time.Second); err == nil {
		t.Fatalf("the Internet answered through a dead exit node: %q", seen)
	}
	l.waitExit(consumer2, exitB, 5*time.Second)
	l.route(consumer, exitB)
	t.Logf("%s through %s %v after the new choice", consumer, exitB, l.waitExit(consumer, exitB, 20*time.Second))
	l.waitExit(consumer2, exitB, 5*time.Second)

	// Exit A comes back and the consumer returns to its primary; exit B
	// still carries consumer 2.
	if err := os.Remove(filepath.Join(l.dir, exitA+".applied")); err != nil {
		t.Fatal(err)
	}
	l.start(exitA, "node")
	l.route(exitA, "serve")
	l.route(consumer, exitA)
	t.Logf("%s back through %s after %v", consumer, exitA, l.waitExit(consumer, exitA, 30*time.Second))
	l.waitExit(consumer2, exitB, 5*time.Second)
	for _, name := range []string{consumer, consumer2} {
		if leaked := l.leaked(name); leaked != "0" {
			t.Fatalf("%s packets left by %s's own network", leaked, name)
		}
	}
}
