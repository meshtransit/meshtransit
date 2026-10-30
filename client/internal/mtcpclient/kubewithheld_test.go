package mtcpclient

import (
	"testing"
	"time"
)

// A withheld table arms one resync; its waits double up to the bound; a
// usable table disarms it and starts again from the first wait.
func TestWithheldResyncBacksOff(t *testing.T) {
	t.Parallel()
	run := &sessionRun{state: &mapState{takesKubernetes: true, takesProfiles: true}}
	run.noteWithheld()
	if run.withheldTimeout() != nil {
		t.Fatal("armed before any table")
	}
	run.state.compiledOnce, run.state.compiled.withheld = true, true
	run.noteWithheld()
	first := run.withheld.timer
	if first == nil || run.withheld.wait != withheldResyncFirst {
		t.Fatalf("not armed: %+v", run.withheld)
	}
	run.noteWithheld()
	if run.withheld.timer != first {
		t.Fatal("armed twice")
	}
	// A resync already waits for its snapshot: none is sent, the wait grows.
	run.resyncing = true
	waits := []time.Duration{}
	for range 7 {
		if err := run.resyncWithheld(); err != nil {
			t.Fatal(err)
		}
		waits = append(waits, run.withheld.wait)
		run.noteWithheld()
	}
	if run.withheld.sent != 0 || run.withheld.pending || waits[0] != 20*time.Second ||
		waits[len(waits)-1] != withheldResyncMax {
		t.Fatalf("waits %v, sent %d", waits, run.withheld.sent)
	}
	run.state.compiled.withheld = false
	run.noteWithheld()
	if run.withheldTimeout() != nil || run.withheld.wait != 0 {
		t.Fatalf("still armed: %+v", run.withheld)
	}
	run.stopWithheld()
	// A node that is no gateway never arms.
	other := &sessionRun{state: &mapState{compiledOnce: true}}
	other.state.compiled.withheld = true
	other.noteWithheld()
	if other.withheldTimeout() != nil {
		t.Fatal("a node that takes no profiles armed")
	}
}
