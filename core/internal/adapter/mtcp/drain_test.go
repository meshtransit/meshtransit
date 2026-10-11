package mtcp

import (
	"context"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func establishedClients(t *testing.T, f *fixture, count int) []*client {
	t.Helper()
	clients := make([]*client, 0, count)
	for range count {
		c, response, err := f.dial(dialOptions{})
		if err != nil || c == nil {
			t.Fatalf("dial: %v %v", response, err)
		}
		c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
		c.expect(sharedmtcp.MessagePong)
		clients = append(clients, c)
	}
	waitFor(t, func() bool { return f.server.Sessions() == count })
	return clients
}

func expectReconnect(t *testing.T, c *client, window time.Duration) {
	t.Helper()
	lifecycle := c.expect(sharedmtcp.MessageLifecycle).(*mtcpv1.Lifecycle)
	if lifecycle.GetState() != mtcpv1.Lifecycle_RECONNECT ||
		time.Duration(lifecycle.GetRetryAfterMs())*time.Millisecond >= max(window, time.Millisecond) {
		t.Fatalf("lifecycle = %+v, want RECONNECT within %v", lifecycle, window)
	}
	if _, _, err := c.receive(); err == nil {
		t.Fatal("session stayed open after RECONNECT")
	}
}

func TestShedAsksSomeSessionsToReconnect(t *testing.T) {
	f := newFixture(t, nil)
	clients := establishedClients(t, f, 3)
	if shed := f.server.Shed(t.Context(), 2, 10*time.Second); shed != 2 {
		t.Fatalf("Shed() = %d, want 2", shed)
	}
	waitFor(t, func() bool { return f.server.Sessions() == 1 })
	reconnects := 0
	for _, c := range clients {
		_ = c.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		t.Run("", func(t *testing.T) {
			kind, message, err := c.receive()
			if err != nil {
				return // the kept session receives nothing
			}
			lifecycle, ok := message.(*mtcpv1.Lifecycle)
			if kind != sharedmtcp.MessageLifecycle || !ok || lifecycle.GetState() != mtcpv1.Lifecycle_RECONNECT ||
				lifecycle.GetRetryAfterMs() >= 10_000 {
				t.Fatalf("shed session got %v %+v", kind, message)
			}
			reconnects++
		})
	}
	if reconnects != 2 {
		t.Fatalf("%d sessions were told to reconnect, want 2", reconnects)
	}
	if f.server.Shed(t.Context(), 0, time.Second) != 0 {
		t.Fatal("Shed(0) shed a session")
	}
}

func TestShutdownSpreadsReconnectsOverTheDrainWindow(t *testing.T) {
	const window = 30 * time.Second
	f := newFixture(t, func(options *Options) { options.DrainWindow = window })
	clients := establishedClients(t, f, 4)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- f.server.Shutdown(ctx)
	}()
	for _, c := range clients {
		expectReconnect(t, c, window)
	}
	if err := <-done; err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if shed := f.server.Shed(t.Context(), 1, time.Second); shed != 0 {
		t.Fatalf("Shed() after shutdown = %d", shed)
	}
}
