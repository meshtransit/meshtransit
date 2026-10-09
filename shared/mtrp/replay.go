package mtrp

// ReplayWindowSize is the number of counters the anti-replay window tracks.
const ReplayWindowSize = 2048

const (
	replayWordBits = 64
	// One extra word: when the window advances, the slot reused for the new
	// highest word must only hold counters already older than the window.
	// Without it, counters near the bottom of the window would be cleared
	// while still in range and could be replayed (RFC 6479 §2).
	replayWords = ReplayWindowSize/replayWordBits + 1
)

// ReplayWindow is a sliding anti-replay filter for CONTROL counters, in the
// style of RFC 6479: a ring of bitmap words indexed by counter, so advancing
// the window clears whole words instead of shifting bits. It accepts each
// counter at most once and rejects counters older than the window.
//
// The zero value is ready to use. ReplayWindow is not safe for concurrent use;
// the owning session serialises access.
type ReplayWindow struct {
	highest uint64
	started bool
	bits    [replayWords]uint64
}

// Accept reports whether counter is new and records it. Call it only after
// the frame has been authenticated, so forged frames cannot move the window.
func (w *ReplayWindow) Accept(counter uint64) bool {
	if !w.started {
		w.started = true
		w.highest = counter
		w.bits = [replayWords]uint64{}
		w.set(counter)
		return true
	}
	if counter > w.highest {
		w.advance(counter)
		w.set(counter)
		return true
	}
	if w.highest-counter >= ReplayWindowSize {
		return false // too old
	}
	if w.isSet(counter) {
		return false // replay
	}
	w.set(counter)
	return true
}

// advance moves the window so that counter becomes the highest, clearing the
// words that fall out of range.
func (w *ReplayWindow) advance(counter uint64) {
	oldWord := w.highest / replayWordBits
	newWord := counter / replayWordBits
	steps := newWord - oldWord
	if steps >= replayWords {
		w.bits = [replayWords]uint64{}
	} else {
		for i := uint64(1); i <= steps; i++ {
			w.bits[(oldWord+i)%replayWords] = 0
		}
	}
	w.highest = counter
}

func (w *ReplayWindow) set(counter uint64) {
	w.bits[(counter/replayWordBits)%replayWords] |= 1 << (counter % replayWordBits)
}

func (w *ReplayWindow) isSet(counter uint64) bool {
	return w.bits[(counter/replayWordBits)%replayWords]&(1<<(counter%replayWordBits)) != 0
}
