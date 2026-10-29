package dataplane

import (
	"net/netip"
	"slices"
	"sync"
)

// addressHolder is a peer holding an address as a single-address allowed
// IP.
type addressHolder struct {
	peer uint64
	key  [32]byte
}

// addressIndex maps the single-address allowed IPs wireguard-go holds to
// their peers. Its own lock keeps PeerKeyAt off the engine's; a lazy
// install or eviction changes only its peer's entries (re-review b5a M-2).
//
// A route another installed peer holds that covers an indexed address does
// not make the address ambiguous: wireguard-go's source check takes the
// longest prefix, so while the /32 is installed only its peer's packets may
// come from it.
type addressIndex struct {
	mu      sync.RWMutex
	holders map[netip.Addr][]addressHolder
}

// keyAt is the key of the one peer holding address; none when no peer or
// peers of two keys hold it.
func (index *addressIndex) keyAt(address netip.Addr) ([32]byte, bool) {
	index.mu.RLock()
	defer index.mu.RUnlock()
	holders := index.holders[address.Unmap()]
	if len(holders) == 0 {
		return [32]byte{}, false
	}
	for _, holder := range holders[1:] {
		if holder.key != holders[0].key {
			return [32]byte{}, false
		}
	}
	return holders[0].key, true
}

// replace indexes peers afresh.
func (index *addressIndex) replace(peers map[uint64]wireGuardPeerState) {
	holders := make(map[netip.Addr][]addressHolder, len(peers))
	for id, peer := range peers {
		for _, address := range singleAddresses(peer.allowedIPs) {
			holders[address] = append(holders[address], addressHolder{peer: id, key: peer.key})
		}
	}
	index.mu.Lock()
	index.holders = holders
	index.mu.Unlock()
}

// add indexes one peer's addresses.
func (index *addressIndex) add(id uint64, peer wireGuardPeerState) {
	index.mu.Lock()
	defer index.mu.Unlock()
	if index.holders == nil {
		index.holders = make(map[netip.Addr][]addressHolder)
	}
	for _, address := range singleAddresses(peer.allowedIPs) {
		index.holders[address] = append(index.holders[address], addressHolder{peer: id, key: peer.key})
	}
}

// remove drops one peer's addresses.
func (index *addressIndex) remove(id uint64, peer wireGuardPeerState) {
	index.mu.Lock()
	defer index.mu.Unlock()
	for _, address := range singleAddresses(peer.allowedIPs) {
		kept := slices.DeleteFunc(index.holders[address], func(holder addressHolder) bool { return holder.peer == id })
		if len(kept) == 0 {
			delete(index.holders, address)
			continue
		}
		index.holders[address] = kept
	}
}

func (index *addressIndex) clear() {
	index.mu.Lock()
	index.holders = nil
	index.mu.Unlock()
}

func singleAddresses(prefixes []netip.Prefix) []netip.Addr {
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsSingleIP() {
			addresses = append(addresses, prefix.Addr().Unmap())
		}
	}
	return addresses
}

// publishAddressKeys indexes the peers wireguard-go holds once a plan is
// adopted; the caller holds e.mu.
func (e *WireGuardEngine) publishAddressKeys() { e.addressKeys.replace(e.peers) }

// withholdChangedAddresses drops from the index, before wireguard-go
// changes its peers, every installed peer the plan removes or changes the
// key or allowed IPs of; the caller holds e.mu.
func (e *WireGuardEngine) withholdChangedAddresses(planned []wireGuardPeerPlan) {
	next := make(map[uint64]wireGuardPeerPlan, len(planned))
	for _, peer := range planned {
		next[peer.id] = peer
	}
	for id, installed := range e.peers {
		if peer, kept := next[id]; kept && peer.key == installed.key &&
			slices.Equal(peer.allowedIPs, installed.allowedIPs) {
			continue
		}
		e.addressKeys.remove(id, installed)
	}
}
