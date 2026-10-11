//go:build integration && darwin

package netadmin

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type utunRead struct {
	at   time.Duration
	size int
	err  error
}

// TestKernelUTUNStaysReadableAfterHandOff follows a utun descriptor the way
// meshnetd and meshd pass it (send, nonblocking wrap, Fd, dup, close) and
// reads it while packets arrive and a second link opens and closes, as the
// DNS link does. Any empty read or error before the end is the EOF that
// stops the WireGuard device. Needs root:
//
//	sudo go test -tags=integration -run TestKernelUTUNStaysReadable -v ./internal/netadmin/
func TestKernelUTUNStaysReadableAfterHandOff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating utun interfaces needs root")
	}
	for _, mode := range []string{"blocking", "pollable"} {
		t.Run(mode, func(t *testing.T) {
			readUTUNAfterHandOff(t, mode == "pollable")
		})
	}
}

func readUTUNAfterHandOff(t *testing.T, pollable bool) {
	address := netip.MustParsePrefix("100.127.250.11/32")
	route := netip.MustParsePrefix("100.127.250.12/32")
	creator := kernelTUNCreator{}
	helperFile, name, err := creator.Open("", 1280, 0, []netip.Prefix{address}, []netip.Prefix{route})
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
	if pollable {
		if err := unix.SetNonblock(adopted, true); err != nil {
			t.Fatal(err)
		}
	}
	reader := os.NewFile(uintptr(adopted), name)

	start := time.Now()
	var mu sync.Mutex
	var reads []utunRead
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			size, err := reader.Read(buffer)
			mu.Lock()
			reads = append(reads, utunRead{at: time.Since(start), size: size, err: err})
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()

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
	_ = reader.Close()
	_, _ = sender.Write([]byte("wake a blocked read"))
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Log("reader still blocked after Close")
	}

	mu.Lock()
	defer mu.Unlock()
	packets := 0
	for _, read := range reads {
		if read.err == nil && read.size > 4 {
			packets++
			continue
		}
		if errors.Is(read.err, os.ErrClosed) {
			continue
		}
		t.Errorf("at %v read %d bytes, error %v", read.at.Round(time.Millisecond), read.size, read.err)
	}
	t.Logf("%s: %d packets read", name, packets)
	if packets == 0 {
		t.Error("no packet reached the utun")
	}
}
