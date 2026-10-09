package endpointpublication

import (
	"context"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

// Store is the least-privilege PostgreSQL reconciliation boundary.
type Store interface {
	ListPublicationCandidates(context.Context, deployment.ID, int) ([]Candidate, error)
	ReadPublicationSnapshot(context.Context, deployment.ID, sharing.PrivateEndpointID) (Snapshot, error)
	StagePublication(context.Context, Snapshot, [32]byte, string) error
	ConfirmPublication(context.Context, Snapshot, [32]byte, string) error
	ListWithdrawalCandidates(context.Context, deployment.ID, int) ([]Candidate, error)
	ReadWithdrawalSnapshot(context.Context, deployment.ID, sharing.PrivateEndpointID) (WithdrawalSnapshot, error)
	FinalizeWithdrawal(context.Context, WithdrawalSnapshot, [32]byte, string) error
}

// Gateway applies and withdraws idempotent endpoint generations. Success means
// the exact command hash is active or absent, respectively.
type Gateway interface {
	Apply(context.Context, Route, [32]byte) error
	Withdraw(context.Context, Withdrawal, [32]byte) error
}
