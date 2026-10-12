//go:build integration && darwin

package netadmin

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	helperSocketEnv = "MESHTRANSIT_HELPER_SOCKET"
	// runningHelperEnv adds a case against the installed meshnetd. Stop meshd
	// first (sudo launchctl bootout system/net.meshtransit.meshd) so it does
	// not compete for the helper.
	runningHelperEnv     = "MESHTRANSIT_USE_RUNNING_HELPER"
	runningHelperSocket  = "/var/run/meshnetd/meshnetd.sock"
	crossProcessAttempts = 20
)

// TestKernelUTUNReachesAnotherProcess opens utuns from a child process, as
// meshd opens them from meshnetd: the descriptor crosses processes by
// SCM_RIGHTS. Each utun is probed on arrival; "shut" means it came with its
// receive side already shut. Cases separate the helper (in this test, or the
// installed meshnetd) from the receiving user (root or _meshd). Needs root:
//
//	sudo MESHTRANSIT_USE_RUNNING_HELPER=1 go test -tags=integration -run TestKernelUTUNReachesAnotherProcess -v ./internal/netadmin/
func TestKernelUTUNReachesAnotherProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating utun interfaces needs root")
	}
	cases := []struct {
		name   string
		user   string
		helper string // "test" or "running"
	}{
		{name: "test-helper-root", user: "root", helper: "test"},
		{name: "test-helper-meshd-user", user: "_meshd", helper: "test"},
	}
	if os.Getenv(runningHelperEnv) == "1" {
		cases = append(cases, struct {
			name   string
			user   string
			helper string
		}{name: "running-meshnetd-meshd-user", user: "_meshd", helper: "running"})
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			account, err := user.Lookup(testCase.user)
			if err != nil {
				t.Skipf("user %s is missing: %v", testCase.user, err)
			}
			uid, _ := strconv.ParseUint(account.Uid, 10, 32)
			gid, _ := strconv.ParseUint(account.Gid, 10, 32)
			socketPath := runningHelperSocket
			if testCase.helper == "test" {
				socketPath = startTestHelper(t, uint32(uid))
			}
			lines := runHandoffClient(t, socketPath, uint32(uid), uint32(gid))
			idle, shut := 0, 0
			for _, line := range lines {
				switch {
				case line == "idle":
					idle++
				case strings.HasPrefix(line, "shut"):
					shut++
					t.Error(line)
				default:
					t.Error(line)
				}
			}
			t.Logf("%d idle, %d shut on arrival", idle, shut)
			if idle+shut == 0 {
				t.Error("the child opened no utun")
			}
		})
	}
}

// TestUTUNHandoffClientProcess is the child: it opens utuns through the
// helper socket and prints "idle" or "shut ..." for each.
func TestUTUNHandoffClientProcess(t *testing.T) {
	socketPath := os.Getenv(helperSocketEnv)
	if socketPath == "" {
		t.Skip("runs only as the child of TestKernelUTUNReachesAnotherProcess")
	}
	output := bufio.NewWriter(os.Stdout)
	defer func() {
		_ = output.Flush()
		os.Exit(0)
	}()
	client, err := NewClient(socketPath, 5*time.Second)
	if err != nil {
		fmt.Fprintln(output, "error", err)
		return
	}
	config := TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.127.250.31/32")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("100.127.250.32/32")},
	}
	for attempt := range crossProcessAttempts {
		tun, err := client.OpenTUN(context.Background(), config)
		if err != nil {
			fmt.Fprintln(output, "error attempt", attempt, err)
			return
		}
		state := probeUTUN(t, tun.File)
		if state == "idle" {
			fmt.Fprintln(output, "idle")
		} else {
			fmt.Fprintln(output, "shut", tun.Name, state)
		}
		_ = output.Flush()
		_ = tun.File.Close()
		// MESHTRANSIT_UTUN_NO_WAIT=1 asks again at once, as meshd does when it
		// rebuilds its data plane.
		if os.Getenv("MESHTRANSIT_UTUN_NO_WAIT") != "1" {
			waitForLinkGone(tun.Name)
		}
	}
}

// startTestHelper serves a meshnetd that accepts uid on a socket uid can use.
func startTestHelper(t *testing.T, uid uint32) string {
	t.Helper()
	server, err := NewServer(ServerOptions{
		AllowedUID:      uid,
		MTU:             1280,
		AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.127.250.0/24")},
		Logger:          slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	socketPath := fmt.Sprintf("/tmp/mt-netadmin-%d-%d.sock", os.Getpid(), uid)
	_ = os.Remove(socketPath)
	listener, err := net.Listen(helperNetwork, socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
		_ = os.Remove(socketPath)
	})
	return socketPath
}

// runHandoffClient runs TestUTUNHandoffClientProcess as uid and returns the
// lines it printed.
func runHandoffClient(t *testing.T, socketPath string, uid, gid uint32) []string {
	t.Helper()
	binary := filepath.Join("/private/tmp", fmt.Sprintf("utun-handoff-%d", os.Getpid()))
	if err := copyExecutable(os.Args[0], binary); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(binary) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestUTUNHandoffClientProcess$")
	command.Env = append(os.Environ(), helperSocketEnv+"="+socketPath)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	output, err := command.Output()
	if err != nil && ctx.Err() != nil {
		t.Fatalf("child did not finish: %v", err)
	}
	var lines []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PASS") || strings.HasPrefix(line, "ok") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
