package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/client/internal/dataplane"
)

// The exit node's status is read every poll with no map stream, and no
// longer once ctx ends (TD-CLI-72).
func TestWatchExitUplinkReadsTheStatusUntilCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var reads atomic.Int32
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			watchExitUplink(ctx, func() dataplane.ExitNodeStatus {
				reads.Add(1)
				return dataplane.ExitNodeStatus{}
			}, 2*time.Second)
			close(done)
		}()
		time.Sleep(7 * time.Second)
		synctest.Wait()
		if got := reads.Load(); got != 4 {
			t.Fatalf("status read %d times in 7 s, want 4 (one at start)", got)
		}
		cancel()
		<-done
		time.Sleep(4 * time.Second)
		if got := reads.Load(); got != 4 {
			t.Fatalf("status read after cancel: %d", got)
		}
	})
}
