package mapsession

import (
	"context"
	"errors"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

// Derive refreshes a running stream's snapshot from its Network's shared
// view (inventory, header and policy, read once per revision for every
// Device) without reading the Device on its own. current is the snapshot
// the stream holds; the result is at least minRevision.
//
// found is false when the caller must read the Device (Reopen): the shared
// view is off or unavailable, the Device has direct projections, or the
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
	cached, found, err := store.inventories.latest(ctx, scope, wanted, time.Now(),
		func(readCtx context.Context) (cachedInventory, error) {
			store.stats.reads.Add(1)
			return store.readInventory(readCtx, scope, scope.WorkspaceID().String(), scope.NetworkID().String())
		})
	if err != nil {
		return appmapsession.Snapshot{}, false, err
	}
	if !found || !cached.serveable || !cached.policy.IsValid() {
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
		MachineKey:        self.MachineKey(),
		NodeKey:           self.NodeKey(),
		Addresses:         self.Addresses(),
		CreatedAt:         self.CreatedAt(),
		KeyExpiry:         self.KeyExpiry(),
		Inventory:         cached.inventory,
		PacketPolicy:      packetPolicy,
		RelayDirectory:    store.relayDirectory(scope.NetworkID()),
	})
	if err != nil {
		return appmapsession.Snapshot{}, false, errors.Join(ErrSnapshotEvidence, err)
	}
	store.stats.derived.Add(1)
	return snapshot, true, nil
}
