package connectivityfeed

import (
	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

// WatchNetwork registers one bounded local consumer. Release is idempotent.
func (feed *Feed) WatchNetwork(
	networkID network.ID,
) (<-chan mapsession.ConnectivityChanged, func(), error) {
	if feed == nil || !networkID.IsValid() {
		return nil, nil, ErrInvalidFeed
	}
	feed.mu.Lock()
	defer feed.mu.Unlock()
	if !feed.started || feed.stopping || feed.watcherCount >= feed.options.MaxWatchers ||
		feed.nextWatcher == ^uint64(0) {
		return nil, nil, ErrFeedUnavailable
	}
	feed.nextWatcher++
	watcherID := feed.nextWatcher
	updates := make(chan mapsession.ConnectivityChanged, 1)
	byNetwork := feed.watchers[networkID]
	if byNetwork == nil {
		byNetwork = make(map[uint64]chan mapsession.ConnectivityChanged)
		feed.watchers[networkID] = byNetwork
	}
	byNetwork[watcherID] = updates
	feed.watcherCount++
	feed.telemetry.watcherOpened()
	return updates, func() { feed.releaseWatcher(networkID, watcherID) }, nil
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

func (feed *Feed) dispatch(change mapsession.ConnectivityChanged) {
	var delivered, coalesced uint64
	feed.mu.Lock()
	for _, updates := range feed.watchers[change.NetworkID()] {
		select {
		case updates <- change:
			delivered++
		default:
			select {
			case <-updates:
			default:
			}
			updates <- change
			coalesced++
		}
	}
	feed.mu.Unlock()
	feed.telemetry.recordWakeup(delivered, coalesced)
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
