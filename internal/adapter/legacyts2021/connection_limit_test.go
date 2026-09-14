package legacyts2021

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestBoundedListenerRejectsExcessSocketsAndReleasesCapacity(t *testing.T) {
	t.Parallel()

	socket := newQueuedListener()
	listener := newBoundedListener(socket, 1)
	firstServer, firstClient := net.Pipe()
	t.Cleanup(func() { _ = firstClient.Close() })
	go func() { socket.connections <- firstServer }()
	first, err := listener.Accept()
	if err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}

	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	secondServer, secondClient := net.Pipe()
	go func() { socket.connections <- secondServer }()
	if err := secondClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("second SetReadDeadline() error = %v", err)
	}
	if _, err := secondClient.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("excess socket read error = %v, want EOF", err)
	}
	_ = secondClient.Close()

	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	thirdServer, thirdClient := net.Pipe()
	t.Cleanup(func() { _ = thirdClient.Close() })
	go func() { socket.connections <- thirdServer }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case third := <-accepted:
		if err := third.Close(); err != nil {
			t.Fatalf("third Close() error = %v", err)
		}
	case err := <-acceptErrors:
		t.Fatalf("second Accept() error = %v", err)
	case <-ctx.Done():
		t.Fatal("released listener capacity was not reused")
	}
	if err := socket.Close(); err != nil {
		t.Fatalf("socket Close() error = %v", err)
	}
}

func TestBoundedConnectionReleasesSlotExactlyOnce(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	releases := 0
	connection := &boundedConnection{
		Conn:    server,
		release: func() { releases++ },
	}
	_ = connection.Close()
	_ = connection.Close()
	if releases != 1 {
		t.Fatalf("releases = %d, want 1", releases)
	}
}
