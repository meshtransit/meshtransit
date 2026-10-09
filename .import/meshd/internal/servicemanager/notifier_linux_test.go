//go:build linux

package servicemanager

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestNotifierAbstractSocket(t *testing.T) {
	address := fmt.Sprintf("@meshd-notify-%d-%d", os.Getpid(), time.Now().UnixNano())
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	t.Setenv(notifySocketEnvironment, address)
	notifier, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	assertNotification(t, listener, func() error {
		return notifier.Ready(context.Background())
	}, "READY=1")
}
