package revisionfeed

import "meshtransit.net/core/internal/domain/network"

// WatchNetwork registers one bounded, process-local consumer. The returned
// release function is idempotent and must be called by the consumer owner.
func (feed *Feed) WatchNetwork(
	networkID network.ID,
) (<-chan network.RevisionAdvanced, func(), error) {
	if feed == nil || !networkID.IsValid() {
		return nil, nil, ErrInvalidFeed
	}

	feed.mu.Lock()
	defer feed.mu.Unlock()
	if !feed.started || feed.stopping || feed.watcherCount >= feed.options.MaxWatchers {
		return nil, nil, ErrFeedUnavailable
	}
	if feed.nextWatcher == ^uint64(0) {
		return nil, nil, ErrFeedUnavailable
	}
	feed.nextWatcher++
	watcherID := feed.nextWatcher
	updates := make(chan network.RevisionAdvanced, 1)
	byNetwork := feed.watchers[networkID]
	if byNetwork == nil {
		byNetwork = make(map[uint64]chan network.RevisionAdvanced)
		feed.watchers[networkID] = byNetwork
	}
	byNetwork[watcherID] = updates
	feed.watcherCount++
	feed.telemetry.watcherOpened()

	release := func() { feed.releaseWatcher(networkID, watcherID) }
	return updates, release, nil
}

func (feed *Feed) releaseWatcher(networkID network.ID, watcherID uint64) {
	feed.mu.Lock()
	defer feed.mu.Unlock()
	byNetwork := feed.watchers[networkID]
	updates, exists := byNetwork[watcherID]
	if !exists {
		return
	}
	delete(byNetwork, watcherID)
	if len(byNetwork) == 0 {
		delete(feed.watchers, networkID)
	}
	close(updates)
	feed.watcherCount--
	feed.telemetry.watcherClosed()
}

func (feed *Feed) dispatch(revision network.RevisionAdvanced) {
	var delivered, coalesced uint64
	feed.mu.Lock()
	for _, updates := range feed.watchers[revision.NetworkID()] {
		if offerLatestRevision(updates, revision) {
			delivered++
		} else {
			coalesced++
		}
	}
	feed.mu.Unlock()
	feed.telemetry.recordWakeup(delivered, coalesced)
}

// offerLatestRevision keeps one bounded, latest-wins mailbox per watcher. The
// feed mutex guarantees this is the only sender and prevents concurrent close.
func offerLatestRevision(
	updates chan network.RevisionAdvanced,
	revision network.RevisionAdvanced,
) bool {
	select {
	case updates <- revision:
		return true
	default:
	}

	select {
	case pending := <-updates:
		if pending.Number() > revision.Number() {
			revision = pending
		}
	default:
		// The consumer drained the mailbox after the first send attempt.
	}
	updates <- revision
	return false
}

func (feed *Feed) stopWatching() {
	feed.mu.Lock()
	feed.stopping = true
	for networkID, byNetwork := range feed.watchers {
		for watcherID, updates := range byNetwork {
			delete(byNetwork, watcherID)
			close(updates)
			feed.telemetry.watcherClosed()
		}
		delete(feed.watchers, networkID)
	}
	feed.watcherCount = 0
	feed.mu.Unlock()
}
