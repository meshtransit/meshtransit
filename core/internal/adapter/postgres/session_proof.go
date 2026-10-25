package postgres

import (
	"context"

	"meshtransit.net/core/internal/domain/node"
)

// markSessionProvenSQL tells the database, for this transaction only, that
// the session proved it holds the node key: schema 226 serves a Kubernetes
// gateway only then.
const markSessionProvenSQL = `SELECT mesh_ops.mark_session_proven_v1($1::BYTEA, $2::BYTEA)`

type sessionProofExecutor interface {
	Exec(context.Context, string, ...any) error
}

// markSessionProven marks nodeKey proven for the machine key in tx when the
// session proved it, before the transaction resolves the session to its
// Device.
func markSessionProven(ctx context.Context, tx sessionProofExecutor, machineFingerprint [32]byte, nodeKey node.Key,
	proven bool) error {
	if !proven {
		return nil
	}
	key := nodeKey.Bytes()
	return tx.Exec(ctx, markSessionProvenSQL, machineFingerprint[:], key[:])
}
