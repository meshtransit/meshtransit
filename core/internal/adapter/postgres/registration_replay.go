package postgres

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

const registrationReplayRollbackWindow = 2 * time.Second

var (
	// ErrInvalidRegistrationReplayStore reports a missing runtime dependency or invalid input.
	ErrInvalidRegistrationReplayStore = errors.New("invalid postgres registration replay store")
	// ErrResolveRegistrationReplay classifies failure to resolve durable idempotency evidence.
	ErrResolveRegistrationReplay = errors.New("resolve postgres registration replay")
	// ErrRegistrationReplayEvidence reports incomplete or malformed committed evidence.
	ErrRegistrationReplayEvidence = errors.New("postgres registration replay evidence is invalid")
)

var _ registration.CommittedResultResolver = (*RegistrationReplayStore)(nil)

// RegistrationReplayStore resolves commit-unknown registration outcomes from
// PostgreSQL. It owns no goroutine or process-local correctness state.
type RegistrationReplayStore struct {
	database registrationReplayDatabase
	metrics  *postgresPoolMetrics
}

// NewRegistrationReplayStore constructs the adapter from a runtime-authenticated pool.
func NewRegistrationReplayStore(pool *Pool) (*RegistrationReplayStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.registrationReplayDatabase == nil {
		return nil, ErrInvalidRegistrationReplayStore
	}
	return newRegistrationReplayStore(pool.registrationReplayDatabase, pool.metrics)
}

func newRegistrationReplayStore(
	database registrationReplayDatabase,
	metrics *postgresPoolMetrics,
) (*RegistrationReplayStore, error) {
	if database == nil {
		return nil, ErrInvalidRegistrationReplayStore
	}
	return &RegistrationReplayStore{database: database, metrics: metrics}, nil
}

// ResolveCommitted returns the immutable completion snapshot for the exact
// command, or found=false when the durable intent has not committed a result.
func (store *RegistrationReplayStore) ResolveCommitted(
	ctx context.Context,
	command registration.Command,
) (result registration.Result, found bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() {
		return registration.Result{}, false, ErrInvalidRegistrationReplayStore
	}
	startedAt := time.Now()
	defer func() {
		store.metrics.observeOperation(
			postgresOperationRegistrationReplay,
			time.Since(startedAt),
			resultErr,
		)
	}()

	transaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return registration.Result{}, false, errors.Join(ErrResolveRegistrationReplay, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		resultErr = errors.Join(resultErr, rollbackRegistrationReplayTransaction(transaction))
	}()

	if err := transaction.Exec(
		ctx,
		setRegistrationReplayScopeSQL,
		command.Scope.WorkspaceID().String(),
		command.Scope.NetworkID().String(),
	); err != nil {
		return registration.Result{}, false, errors.Join(
			ErrResolveRegistrationReplay,
			fmt.Errorf("set exact scope: %w", err),
		)
	}

	var record registrationReplayRecord
	err = transaction.QueryRow(
		ctx,
		loadRegistrationReplaySQL,
		command.RegistrationID.String(),
	).Scan(
		&record.intentFormatVersion,
		&record.state,
		&record.requestHash,
		&record.machineFingerprint,
		&record.requestedNodeKey,
		&record.credentialPublicID,
		&record.nodePublicID,
		&record.completedHostname,
		&record.completedDisposition,
		&record.completedNetworkRevision,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return registration.Result{}, false, errors.Join(
			ErrResolveRegistrationReplay,
			fmt.Errorf("query completion evidence: %w", err),
		)
	}
	if err == nil && record.state == "completed" {
		result, err = record.resultFor(command)
		if err != nil {
			return registration.Result{}, false, errors.Join(ErrResolveRegistrationReplay, err)
		}
		found = true
	}

	if err := transaction.Commit(ctx); err != nil {
		return registration.Result{}, false, errors.Join(
			ErrResolveRegistrationReplay,
			fmt.Errorf("commit completion read: %w", err),
		)
	}
	committed = true
	return result, found, nil
}

type registrationReplayRecord struct {
	intentFormatVersion      int16
	state                    string
	requestHash              []byte
	machineFingerprint       []byte
	requestedNodeKey         []byte
	credentialPublicID       string
	nodePublicID             sql.NullString
	completedHostname        sql.NullString
	completedDisposition     sql.NullString
	completedNetworkRevision sql.NullInt64
}

func (record registrationReplayRecord) resultFor(
	command registration.Command,
) (registration.Result, error) {
	if record.intentFormatVersion != 2 || record.state != "completed" ||
		!record.nodePublicID.Valid || !record.completedHostname.Valid ||
		!record.completedDisposition.Valid || !record.completedNetworkRevision.Valid {
		return registration.Result{}, ErrRegistrationReplayEvidence
	}

	credentialID, err := enrollment.ParseCredentialID(record.credentialPublicID)
	if err != nil {
		return registration.Result{}, ErrRegistrationReplayEvidence
	}
	requestHash, err := registrationRequestHash(record.requestHash)
	if err != nil {
		return registration.Result{}, err
	}
	expectedRequestHash, err := command.RequestHash()
	if err != nil {
		return registration.Result{}, registration.ErrInvalidCommand
	}
	machineFingerprint := command.Identity.MachineKey().Fingerprint()
	requestedNodeKey := command.Identity.NodeKey().Bytes()
	if credentialID != command.CredentialID || requestHash != expectedRequestHash ||
		subtle.ConstantTimeCompare(record.machineFingerprint, machineFingerprint[:]) != 1 ||
		subtle.ConstantTimeCompare(record.requestedNodeKey, requestedNodeKey[:]) != 1 {
		return registration.Result{}, registration.ErrIntentConflict
	}

	nodeID, err := node.ParseID(record.nodePublicID.String)
	if err != nil {
		return registration.Result{}, ErrRegistrationReplayEvidence
	}
	hostname, err := node.ParseHostname(record.completedHostname.String)
	if err != nil {
		return registration.Result{}, ErrRegistrationReplayEvidence
	}
	disposition, err := registrationDisposition(record.completedDisposition.String)
	if err != nil {
		return registration.Result{}, err
	}
	result, err := registration.NewResult(
		command.RegistrationID,
		command.Scope,
		nodeID,
		hostname,
		disposition,
		record.completedNetworkRevision.Int64,
	)
	if err != nil {
		return registration.Result{}, ErrRegistrationReplayEvidence
	}
	return result, nil
}

func registrationRequestHash(value []byte) (registration.RequestHash, error) {
	if len(value) != 32 {
		return registration.RequestHash{}, ErrRegistrationReplayEvidence
	}
	var bytes [32]byte
	copy(bytes[:], value)
	hash, err := registration.NewRequestHash(bytes)
	if err != nil {
		return registration.RequestHash{}, ErrRegistrationReplayEvidence
	}
	return hash, nil
}

func registrationDisposition(value string) (registration.Disposition, error) {
	switch value {
	case "created":
		return registration.DispositionCreated, nil
	case "resumed":
		return registration.DispositionResumed, nil
	default:
		return registration.DispositionUnknown, ErrRegistrationReplayEvidence
	}
}

func rollbackRegistrationReplayTransaction(transaction registrationReplayTransaction) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), registrationReplayRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back registration replay transaction: %w", err)
	}
	return nil
}
