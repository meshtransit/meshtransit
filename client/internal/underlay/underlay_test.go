package underlay

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

// The tests share the process-wide protector, so none runs in parallel.

func installRecorder(t *testing.T, fail bool) *recorder {
	t.Helper()
	record := &recorder{fail: fail}
	SetProtector(record.protect)
	t.Cleanup(func() { SetProtector(nil) })
	return record
}

type recorder struct {
	mu   sync.Mutex
	fds  []uintptr
	fail bool
}

func (r *recorder) protect(fd uintptr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fds = append(r.fds, fd)
	if r.fail {
		return errors.New("VPN service gone")
	}
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.fds)
}

func TestWithoutAProtectorSocketsOpenUnchanged(t *testing.T) {
	if Active() {
		t.Fatal("Active() = true with no protector")
	}
	if err := Protect(3); err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	conn, err := ListenConfig().ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestDialerProtectsEachSocketBeforeItConnects(t *testing.T) {
	record := installRecorder(t, false)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	conn, err := Dialer(0).DialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	_ = conn.Close()
	packet, err := ListenConfig().ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	_ = packet.Close()
	if record.count() != 2 {
		t.Fatalf("protected %d sockets, want 2", record.count())
	}
}

func TestAnUnprotectedSocketIsNeverUsed(t *testing.T) {
	installRecorder(t, true)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if conn, err := Dialer(0).DialContext(t.Context(), "tcp4", listener.Addr().String()); !errors.Is(err, ErrNotProtected) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("DialContext() error = %v, want ErrNotProtected", err)
	}
	if _, err := ListenConfig().ListenPacket(t.Context(), "udp4", "127.0.0.1:0"); !errors.Is(err, ErrNotProtected) {
		t.Fatalf("ListenPacket() error = %v, want ErrNotProtected", err)
	}
}

func TestSetProtectorNilRemovesIt(t *testing.T) {
	installRecorder(t, true)
	SetProtector(nil)
	if Active() || Protect(3) != nil {
		t.Fatal("protector still installed")
	}
}
