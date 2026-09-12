package servicemanager

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDisabledNotifier(t *testing.T) {
	t.Setenv(notifySocketEnvironment, "")
	notifier, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, present := os.LookupEnv(notifySocketEnvironment); present {
		t.Fatal("New() retained NOTIFY_SOCKET")
	}
	if err := notifier.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	if err := notifier.Stopping(context.Background()); err != nil {
		t.Fatalf("Stopping() error = %v", err)
	}
}

func TestNewRejectsInvalidAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{name: "relative", address: "run/systemd/notify"},
		{name: "empty abstract", address: "@"},
		{name: "too long", address: "/" + strings.Repeat("a", maxNotifySocketBytes)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(notifySocketEnvironment, test.address)
			if _, err := New(); err == nil {
				t.Fatal("New() error = nil")
			}
			if _, present := os.LookupEnv(notifySocketEnvironment); present {
				t.Fatal("New() retained invalid NOTIFY_SOCKET")
			}
		})
	}
}

func TestNotifierLifecycle(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "meshd-notify-test.")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	path := filepath.Join(directory, "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	t.Setenv(notifySocketEnvironment, path)
	notifier, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	assertNotification(t, listener, func() error {
		return notifier.Ready(context.Background())
	}, "READY=1")
	assertNotification(t, listener, func() error {
		return notifier.Stopping(context.Background())
	}, "STOPPING=1")
}

func TestNotifierFailsWhenSocketIsUnavailable(t *testing.T) {
	t.Setenv(notifySocketEnvironment, "/run/meshd-test/missing-notify.sock")
	notifier, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := notifier.Ready(context.Background()); err == nil {
		t.Fatal("Ready() error = nil")
	}
}

func TestNotifierHonorsCanceledContext(t *testing.T) {
	t.Setenv(notifySocketEnvironment, "/run/meshd-test/missing-notify.sock")
	notifier, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := notifier.Ready(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ready() error = %v, want context.Canceled", err)
	}
}

func assertNotification(
	t *testing.T,
	listener *net.UnixConn,
	send func() error,
	want string,
) {
	t.Helper()
	if err := send(); err != nil {
		t.Fatalf("send notification error = %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buffer := make([]byte, 64)
	read, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatalf("ReadFromUnix() error = %v", err)
	}
	if got := string(buffer[:read]); got != want {
		t.Fatalf("notification = %q, want %q", got, want)
	}
}
