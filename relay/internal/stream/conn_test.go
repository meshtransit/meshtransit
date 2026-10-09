package stream

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

// stuckFramer never completes a write, like a client that stopped reading.
type stuckFramer struct{ release chan struct{} }

func (f stuckFramer) ReadFrame() ([]byte, error) { <-f.release; return nil, errFrameSize }
func (f stuckFramer) WriteFrame([]byte) error    { <-f.release; return errFrameSize }
func (f stuckFramer) Close() error {
	select {
	case <-f.release:
	default:
		close(f.release)
	}
	return nil
}

func TestSendQueueIsBoundedByBytes(t *testing.T) {
	t.Parallel()
	c := newConn(stuckFramer{release: make(chan struct{})}, netip.Addr{}, func(string) {})
	go c.write()
	frame := bytes.Repeat([]byte{1}, 4000)
	accepted := 0
	for range 100 {
		if err := c.Send(frame); err != nil {
			if !errors.Is(err, errQueueFull) {
				t.Fatal(err)
			}
			break
		}
		accepted++
	}
	// One frame may already sit in the stuck writer; the rest are queued.
	if queued := c.queued.Load(); queued > maxQueuedBytes || accepted > maxQueuedBytes/len(frame)+1 {
		t.Fatalf("accepted %d frames, %d bytes queued", accepted, queued)
	}
	_ = c.Close()
}
