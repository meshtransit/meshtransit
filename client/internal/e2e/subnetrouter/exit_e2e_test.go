//go:build e2e && linux

package subnetrouter

import (
	"context"
	"os/exec"
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
	l := newBareLab(t, "hub", consumer, exitA, exitB, "net", "lan")
	l.scenario = "exit"
	hub := l.ns("hub")
	for _, bridge := range []string{"bu", "bx", "bi", "bl"} {
		l.ip("-n", hub, "link", "add", bridge, "type", "bridge")
		l.ip("-n", hub, "link", "set", bridge, "up")
	}
	l.ip("-n", hub, "addr", "add", egressGateway.String()+"/24", "dev", "bx")
	l.ip("-n", hub, "addr", "add", netGateway.String()+"/24", "dev", "bi")
	l.exec(hub, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	for _, name := range []string{consumer, exitA, exitB} {
		l.attach(name, "under0", "bu", nodes[name].underlay.String()+"/24")
	}
	for _, name := range []string{exitA, exitB} {
		l.attach(name, "egress0", "bx", nodes[name].lan.String()+"/24")
		l.ip("-n", l.ns(name), "route", "add", "default", "via", egressGateway.String())
	}
	l.attach(exitA, "lan0", "bl", "10.50.0.2/24")
	l.attach("lan", "lan0", "bl", lanHost.String()+"/24")
	l.attach("net", "net0", "bi", netHost.String()+"/24")
	l.ip("-n", l.ns("net"), "route", "add", "default", "via", netGateway.String())
	l.ip("-n", l.ns(consumer), "route", "add", "default", "via", "10.99.0.254")
	l.ip("-n", l.ns(consumer), "route", "add", "34.10.0.0/24", "via", "10.99.0.254")
	l.exec(l.ns(consumer), "nft", "add", "table", "inet", "leak")
	l.exec(l.ns(consumer), "nft", "add", "chain", "inet", "leak", "out",
		"{ type filter hook output priority -300; }")
	l.exec(l.ns(consumer), "nft", "add", "rule", "inet", "leak", "out",
		"oifname", "under0", "ip", "daddr", "34.10.0.0/24", "counter")
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

// leaked returns how many packets the consumer sent to the Internet host by
// its own network.
func (l *lab) leaked() string {
	l.t.Helper()
	//nolint:gosec // the test's own namespace
	output, err := exec.CommandContext(context.Background(), "ip", "netns", "exec", l.ns(consumer),
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

// waitExit waits until the Internet host sees the consumer arrive from
// exit's egress address.
func (l *lab) waitExit(exit string, timeout time.Duration) time.Duration {
	l.t.Helper()
	want := nodes[exit].lan.String()
	started := time.Now()
	last := ""
	for time.Since(started) < timeout {
		seen, err := l.run("whonet", 3*time.Second)
		if err == nil && seen == want {
			return time.Since(started)
		}
		last = seen
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatalf("the Internet host never saw %s through %s; last %q", want, exit, last)
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
	l.route(consumer, exitA)
	t.Logf("through %s after %v", exitA, l.waitExit(exitA, 30*time.Second))

	// The exit node's LAN is no Internet.
	if seen, err := l.run("who", 5*time.Second); err == nil {
		t.Fatalf("the consumer reached the exit node's LAN: %q", seen)
	}

	l.stop(exitA, syscall.SIGKILL)
	l.route(consumer, exitB)
	t.Logf("through %s %v after the new choice", exitB, l.waitExit(exitB, 20*time.Second))

	// No exit node: the Internet is unreachable, and nothing leaves by the
	// consumer's own network.
	l.route(consumer, none)
	if seen, err := l.run("whonet", 5*time.Second); err == nil {
		t.Fatalf("the Internet answered without an exit node: %q", seen)
	}
	if leaked := l.leaked(); leaked != "0" {
		t.Fatalf("%s packets left by the consumer's own network", leaked)
	}
	l.route(consumer, exitB)
	l.waitExit(exitB, 20*time.Second)
}
