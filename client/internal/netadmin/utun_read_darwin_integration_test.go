//go:build integration && darwin

package netadmin

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const utunReaderEnv = "MESHTRANSIT_UTUN_READER"

type utunReadCase struct {
	name     string
	pollable bool
	ipv6     bool
	// reader, when set, reads in a child process running as this user, as
	// meshd reads as _meshd.
	reader string
}

// TestKernelUTUNStaysReadableAfterHandOff follows a utun descriptor the way
// meshnetd and meshd pass it (send, nonblocking wrap, Fd, dup, close) and
// reads it while packets arrive and a second link opens and closes, as the
// DNS link does. Any empty read or error before the end is the EOF that
// stops the WireGuard device. The cases add what meshd does on top: an IPv6
// address on the link and a reader running as _meshd. Needs root:
//
//	sudo go test -tags=integration -run TestKernelUTUNStaysReadable -v ./internal/netadmin/
func TestKernelUTUNStaysReadableAfterHandOff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating utun interfaces needs root")
	}
	for _, testCase := range []utunReadCase{
		{name: "blocking"},
		{name: "pollable", pollable: true},
		{name: "blocking-ipv6", ipv6: true},
		{name: "meshd-user", reader: "_meshd"},
		{name: "meshd-user-ipv6", ipv6: true, reader: "_meshd"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			readUTUNAfterHandOff(t, testCase)
		})
	}
}

// TestUTUNReaderProcess is the child reader: it reads descriptor 3 and prints
// one line per read ("packet N" or "empty" or "error ...") until stopped.
func TestUTUNReaderProcess(t *testing.T) {
	if os.Getenv(utunReaderEnv) != "1" {
		t.Skip("runs only as the child of TestKernelUTUNStaysReadableAfterHandOff")
	}
	file := os.NewFile(3, "utun")
	output := bufio.NewWriter(os.Stdout)
	buffer := make([]byte, 2048)
	for empties := 0; empties < 100; {
		size, err := file.Read(buffer)
		switch {
		case size == 0 && (err == nil || errors.Is(err, io.EOF)):
			empties++
			fmt.Fprintln(output, "empty")
		case err != nil:
			fmt.Fprintln(output, "error", err)
			_ = output.Flush()
			os.Exit(0)
		default:
			fmt.Fprintln(output, "packet", size)
		}
		_ = output.Flush()
	}
	os.Exit(0)
}

func readUTUNAfterHandOff(t *testing.T, testCase utunReadCase) {
	addresses := []netip.Prefix{netip.MustParsePrefix("100.127.250.11/32")}
	if testCase.ipv6 {
		addresses = append(addresses, netip.MustParsePrefix("fd07:d4de:9d87:fff::11/128"))
	}
	route := netip.MustParsePrefix("100.127.250.12/32")
	creator := kernelTUNCreator{}
	helperFile, name, err := creator.Open("", 1280, 0, addresses, []netip.Prefix{route})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	// The descriptor meshd receives, after meshnetd closes its own.
	received, err := unix.Dup(int(helperFile.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = helperFile.Close()
	// netadmin client: nonblocking os.File.
	if err := unix.SetNonblock(received, true); err != nil {
		t.Fatal(err)
	}
	clientFile := os.NewFile(uintptr(received), "meshnetd-tun")
	// dataplane: duplicate, close the client's file, wrap the duplicate.
	adopted, err := unix.FcntlInt(clientFile.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = clientFile.Close()
	if testCase.pollable {
		if err := unix.SetNonblock(adopted, true); err != nil {
			t.Fatal(err)
		}
	}
	reader := os.NewFile(uintptr(adopted), name)

	var collect func() []string
	if testCase.reader != "" {
		collect = readInChild(t, reader, testCase.reader)
	} else {
		collect = readInProcess(reader)
	}

	sender, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(route.Addr(), 9)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	var dnsLink *os.File
	for tick := range 40 {
		switch tick {
		case 10: // like the DNS link: a second utun without routes
			dnsLink, _, err = creator.Open("", 1280, 0, []netip.Prefix{}, []netip.Prefix{})
			if err != nil {
				t.Errorf("second link: %v", err)
			}
		case 20:
			if dnsLink != nil {
				_ = dnsLink.Close()
			}
		}
		_, _ = sender.Write([]byte("meshtransit utun probe"))
		time.Sleep(100 * time.Millisecond)
	}

	packets := 0
	for _, line := range collect() {
		if strings.HasPrefix(line, "packet ") {
			packets++
			continue
		}
		t.Errorf("%s: %s", name, line)
	}
	t.Logf("%s: %d packets read", name, packets)
	if packets == 0 {
		t.Error("no packet reached the utun")
	}
}

// readInProcess reads reader here; collect closes it and returns the reads.
func readInProcess(reader *os.File) func() []string {
	var mu sync.Mutex
	var lines []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for empties := 0; empties < 100; {
			size, err := reader.Read(buffer)
			mu.Lock()
			switch {
			case size == 0 && (err == nil || errors.Is(err, io.EOF)):
				empties++
				lines = append(lines, "empty")
			case errors.Is(err, os.ErrClosed):
				mu.Unlock()
				return
			case err != nil:
				lines = append(lines, "error "+err.Error())
				mu.Unlock()
				return
			default:
				lines = append(lines, "packet "+strconv.Itoa(size))
			}
			mu.Unlock()
		}
	}()
	return func() []string {
		_ = reader.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

// readInChild hands reader to a copy of this test binary running as
// username; collect stops it and returns the reads it printed.
func readInChild(t *testing.T, reader *os.File, username string) func() []string {
	t.Helper()
	account, err := user.Lookup(username)
	if err != nil {
		t.Skipf("user %s is missing: %v", username, err)
	}
	uid, _ := strconv.ParseUint(account.Uid, 10, 32)
	gid, _ := strconv.ParseUint(account.Gid, 10, 32)
	// The go test binary sits in root's private temp directory.
	binary := filepath.Join("/private/tmp", fmt.Sprintf("utun-reader-%d", os.Getpid()))
	if err := copyExecutable(os.Args[0], binary); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(binary) })

	command := exec.Command(binary, "-test.run=^TestUTUNReaderProcess$")
	command.Env = append(os.Environ(), utunReaderEnv+"=1")
	command.ExtraFiles = []*os.File{reader}
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	var mu sync.Mutex
	var lines []string
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "PASS") || strings.HasPrefix(line, "ok") {
				continue
			}
			mu.Lock()
			lines = append(lines, line)
			mu.Unlock()
		}
	}()
	return func() []string {
		_ = command.Process.Kill()
		_ = command.Wait()
		<-scanned
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func copyExecutable(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o755)
}
