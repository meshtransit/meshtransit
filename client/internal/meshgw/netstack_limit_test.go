package meshgw

import "testing"

// netstackSlots bounds how many netstack tests run at once. Each one moves
// real TCP through gVisor with deadlines of a few seconds; sixteen at once
// under -race starve each other past those deadlines (TD-TEST-58).
var netstackSlots = make(chan struct{}, 2)

// parallelNetstack marks a netstack test parallel and waits for a slot,
// held until its cleanups (stacks closed) have run.
func parallelNetstack(t *testing.T) {
	t.Helper()
	t.Parallel()
	netstackSlots <- struct{}{}
	t.Cleanup(func() { <-netstackSlots })
}
