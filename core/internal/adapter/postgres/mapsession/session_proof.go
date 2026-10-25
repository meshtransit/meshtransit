package mapsession

import (
	"context"

	"meshtransit.net/core/internal/control"
)

// markSessionProven runs markSessionProvenSQL when identity is proven.
func markSessionProven(ctx context.Context, transaction databaseTransaction, identity control.AuthenticatedNode) error {
	if !identity.Proven() {
		return nil
	}
	fingerprint := identity.MachineFingerprint()
	key := identity.NodeKey().Bytes()
	return transaction.Exec(ctx, markSessionProvenSQL, fingerprint[:], key[:])
}
