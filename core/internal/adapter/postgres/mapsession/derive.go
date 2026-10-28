package mapsession

import (
	"context"
	"errors"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

// Derive refreshes a running stream's snapshot from its Network's shared
// view (inventory, header and policy, read once per revision for every
// Device) without reading the Device on its own. current is the snapshot
// the stream holds; the result is at least minRevision.
//
// found is false when the caller must read the Device (Reopen): the shared
// view is off or unavailable, the Device has direct projections, a Device
// share binds it (which a snapshot opened before the share took effect does
// not reflect), or the
// view does not list the Device exactly as current (suspended, revoked,
// re-registered or rekeyed). A view lists a Device only when every check of
// the authenticated scope read passes for it, so a Device it lists is one
// that read would admit.
func (store *Store) Derive(
	ctx context.Context,
	current appmapsession.Snapshot,
	minRevision int64,
) (appmapsession.Snapshot, bool, error) {
	if ctx == nil || store == nil || store.inventories == nil || !current.IsValid() || current.HasDirectProjections() {
		return appmapsession.Snapshot{}, false, nil
	}
	scope := current.Scope()
	wanted := max(minRevision, current.NetworkRevision())
	cached, found, err := store.inventories.latest(ctx, scope, wanted,
		func(readCtx context.Context, previous cachedInventory) (cachedInventory, error) {
			store.stats.reads.Add(1)
			return store.readInventory(readCtx, scope, scope.WorkspaceID().String(), scope.NetworkID().String(), previous)
		})
	if err != nil {
		return appmapsession.Snapshot{}, false, err
	}
	if !found || !cached.serveable || !cached.policy.IsValid() {
		return appmapsession.Snapshot{}, false, nil
	}
	if cached.sharingBinds(current.NumericNodeID()) {
		store.stats.sharingDeclines.Add(1)
		return appmapsession.Snapshot{}, false, nil
	}
	self, listed := cached.inventory.Device(current.NodeID())
	if !listed || self.NumericNodeID() != current.NumericNodeID() || self.MachineKey() != current.MachineKey() ||
		self.NodeKey() != current.NodeKey() || self.SessionGeneration() != current.SessionGeneration() ||
		cached.recoveryEpoch != current.RecoveryEpoch() {
		return appmapsession.Snapshot{}, false, nil
	}
	// The expansion is stable until the view's earliest lapse, which freshAt
	// keeps ahead of now, so expanding at the read time equals expanding now.
	packetPolicy, err := cached.policy.For(self.NodeID(), cached.readAt, store.options.PolicyRuleLimit)
	if errors.Is(err, appmapsession.ErrPacketPolicyLimit) {
		return appmapsession.Snapshot{}, false, nil // the Device's own read reports the limit
	}
	if err != nil {
		return appmapsession.Snapshot{}, false, errors.Join(ErrSnapshotEvidence, err)
	}
	// The session's capabilities filter routes before the build, so a
	// refresh of a client without them never rebuilds the snapshot.
	routes := cached.policy.RoutesFor(self.NodeID(), cached.readAt)
	if capabilities, known := current.RouteCapabilities(); known {
		routes = routes.ForCapabilities(capabilities)
	}
	// A gateway's peers' access may change between two reads of the view
	// (an owner's membership ends), so it is computed at the database's
	// time now rather than the read's; every other change comes with a
	// reread before it takes effect.
	// A map that carried access and now withholds it is counted once.
	kubernetes := store.kubernetesView(cached, self.NodeID(), cached.databaseNow(), current.Kubernetes().Computed())
	selfLabel, _ := self.DNSLabel()
	snapshot, err := appmapsession.NewSnapshot(appmapsession.SnapshotParams{
		Scope:             scope,
		NetworkName:       cached.networkName,
		NetworkRevision:   cached.revision,
		RecoveryEpoch:     cached.recoveryEpoch,
		SessionGeneration: self.SessionGeneration(),
		NumericNodeID:     self.NumericNodeID(),
		NumericOwnerID:    self.NumericOwnerID(),
		NodeID:            self.NodeID(),
		Hostname:          self.Hostname(),
		DNSLabel:          selfLabel,
		WorkspaceCode:     cached.workspaceCode,
		NetworkCode:       cached.networkCode,
		MachineKey:        self.MachineKey(),
		NodeKey:           self.NodeKey(),
		Addresses:         self.Addresses(),
		CreatedAt:         self.CreatedAt(),
		KeyExpiry:         self.KeyExpiry(),
		DatabaseReadAt:    cached.readAt,
		ReadAtLocal:       cached.readLocal,
		Inventory:         cached.inventory,
		PacketPolicy:      packetPolicy,
		Routes:            routes,
		Kubernetes:        kubernetes,
		RelayDirectory:    store.relayDirectory(scope.NetworkID()),
	})
	if err != nil {
		return appmapsession.Snapshot{}, false, errors.Join(ErrSnapshotEvidence, err)
	}
	store.stats.derived.Add(1)
	return snapshot, true, nil
}

// Unchanged implements SnapshotViewChecker: current still describes its
// Network when it was built from the latest shared view (the same objects,
// which an identical reread keeps), at that view's revision and policy
// revision, with the same header and relay directory, and no policy or key
// deadline is near; for a gateway's map, its peers' Kubernetes access
// computed now is still what it carries (an owner's membership ending moves
// no revision and no ChangesAt). Maps with direct projections, cut to a peer
// limit or of a Device a share binds are always rebuilt.
func (store *Store) Unchanged(ctx context.Context, current appmapsession.Snapshot, minRevision int64) (bool, error) {
	if ctx == nil || store == nil || store.inventories == nil || !current.IsValid() ||
		current.HasDirectProjections() || current.IsPeerLimited() || minRevision > current.NetworkRevision() {
		return false, nil
	}
	scope := current.Scope()
	cached, found, err := store.inventories.latest(ctx, scope, current.NetworkRevision(),
		func(readCtx context.Context, previous cachedInventory) (cachedInventory, error) {
			store.stats.reads.Add(1)
			return store.readInventory(readCtx, scope, scope.WorkspaceID().String(), scope.NetworkID().String(), previous)
		})
	if err != nil || !found {
		return false, err
	}
	if cached.sharingBinds(current.NumericNodeID()) {
		store.stats.sharingDeclines.Add(1)
		return false, nil
	}
	changesAt := cached.policy.ChangesAt()
	directory := store.relayDirectory(scope.NetworkID())
	unchanged := cached.serveable && cached.policy.IsValid() && cached.revision == current.NetworkRevision() &&
		cached.policy.Revision() == current.PacketPolicy().Revision() && current.SharesInventory(cached.inventory) &&
		cached.networkName == current.NetworkName() && cached.recoveryEpoch == current.RecoveryEpoch() &&
		sameDisplayCodes(cached, current) &&
		(changesAt.IsZero() || cached.databaseNow().Add(clockMargin).Before(changesAt)) &&
		directory.Revision() == current.RelayDirectory().Revision() &&
		directory.Fingerprint() == current.RelayDirectory().Fingerprint()
	// Equal access has the same earliest grant, so the same refresh time:
	// once it passed, that grant is gone and the map is rebuilt. A refresh
	// time the view's own clock has reached rebuilds it too, so a timer that
	// fired early on the snapshot's clock never spins on an unchanged map.
	if unchanged && current.Kubernetes().Computed() {
		now := cached.databaseNow()
		refreshAt := current.Kubernetes().RefreshAt()
		view := store.kubernetesView(cached, current.NodeID(), now, false)
		if _, known := current.Kubernetes().CA(); !known {
			// A session without gateway.cert1 carries no CAs (review a3b2
			// H1); the same revision and inventory hold the same CAs.
			view = view.WithoutCA()
		}
		unchanged = (refreshAt.IsZero() || now.Before(refreshAt)) && view.Equal(current.Kubernetes())
	}
	if unchanged {
		store.stats.unchanged.Add(1)
	}
	return unchanged, nil
}

// sameDisplayCodes reports whether current names its zone with the view's
// display codes.
func sameDisplayCodes(cached cachedInventory, current appmapsession.Snapshot) bool {
	workspaceCode, networkCode, _ := current.DisplayCodes()
	return workspaceCode == cached.workspaceCode && networkCode == cached.networkCode
}
