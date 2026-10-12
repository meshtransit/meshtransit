//go:build linux || darwin

package netadmin

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestWriteResponseKeepsTheDescriptorUntilReceipt checks that a response
// carrying a descriptor returns only after the receiver closed its end, so
// the sender's copy outlives the descriptor's time in flight.
func TestWriteResponseKeepsTheDescriptorUntilReceipt(t *testing.T) {
	t.Parallel()
	path := fmt.Sprintf("/tmp/mt-receipt-%d.sock", os.Getpid())
	_ = os.Remove(path)
	listener, err := net.ListenUnix(helperNetwork, &net.UnixAddr{Name: path, Net: helperNetwork})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	var receiverClosed atomic.Bool
	written := make(chan bool, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			written <- false
			return
		}
		defer func() { _ = connection.Close() }()
		_ = connection.SetDeadline(time.Now().Add(helperOperationTimeout))
		err = writeResponse(connection, response{Version: protocolVersion, OK: true}, reader)
		written <- err == nil && receiverClosed.Load()
	}()

	connection, err := net.DialUnix(helperNetwork, nil, &net.UnixAddr{Name: path, Net: helperNetwork})
	if err != nil {
		t.Fatal(err)
	}
	_, descriptors, err := readResponseFrame(connection)
	if err != nil || len(descriptors) != 1 {
		t.Fatalf("readResponseFrame() = %d descriptors, %v", len(descriptors), err)
	}
	closeDescriptors(descriptors)
	time.Sleep(100 * time.Millisecond)
	receiverClosed.Store(true)
	_ = connection.Close()
	select {
	case ok := <-written:
		if !ok {
			t.Fatal("writeResponse returned before the receiver closed its end")
		}
	case <-time.After(helperOperationTimeout + time.Second):
		t.Fatal("writeResponse did not return after the receiver closed its end")
	}
}
