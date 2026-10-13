package mapsession

import "time"

// A stream whose refreshes are expensive (a Device taking part in thousands
// of shares, whose map re-proves every share) spaces the refreshes that
// revision wakeups ask for: a wakeup arriving sooner than the spacing after
// the last refresh is held and merged with the next ones into one refresh
// at the end of the spacing. Every refresh still re-reads the whole map from
// PostgreSQL; pacing only bounds how often, so a change reaches such a
// Device at most refreshSpacingMaximum later. Deadlines (authority, share
// projection, relay grant), reconciles and connectivity changes are never
// held.
const (
	// refreshPacingThreshold: refreshes faster than this are never spaced.
	refreshPacingThreshold = 250 * time.Millisecond
	// refreshSpacingFactor times the last refresh's duration is the spacing,
	// so a paced stream spends at most a third of its time refreshing.
	refreshSpacingFactor  = 3
	refreshSpacingMinimum = time.Second
	refreshSpacingMaximum = 10 * time.Second
)

// refreshPacer holds one stream's pacing state; the stream loop owns it.
type refreshPacer struct {
	lastAt  time.Time
	spacing time.Duration
	// pending: a held wakeup awaits the refresh due at lastAt + spacing;
	// pendingRevision is the highest own-Network revision held (0 if none).
	pending         bool
	pendingRevision int64
}

// refreshed records a full refresh that ended at now after took, and clears
// any held wakeup: the refresh read PostgreSQL after it was announced.
func (pacer *refreshPacer) refreshed(now time.Time, took time.Duration) {
	pacer.lastAt = now
	pacer.pending, pacer.pendingRevision = false, 0
	if took < refreshPacingThreshold {
		pacer.spacing = 0
		return
	}
	pacer.spacing = min(max(refreshSpacingFactor*took, refreshSpacingMinimum), refreshSpacingMaximum)
}

// hold reports whether a revision wakeup arriving at now must wait, and if
// so merges it: ownRevision is the revision it announces for the stream's
// own Network, or 0 for another Network's.
func (pacer *refreshPacer) hold(now time.Time, ownRevision int64) bool {
	if pacer.spacing == 0 || !now.Before(pacer.lastAt.Add(pacer.spacing)) {
		return false
	}
	pacer.pending = true
	pacer.pendingRevision = max(pacer.pendingRevision, ownRevision)
	return true
}

// due returns when the held refresh is due, or false when none is held.
func (pacer *refreshPacer) due() (time.Time, bool) {
	if !pacer.pending {
		return time.Time{}, false
	}
	return pacer.lastAt.Add(pacer.spacing), true
}
