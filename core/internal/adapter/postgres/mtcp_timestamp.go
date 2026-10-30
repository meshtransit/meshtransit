package postgres

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
)

const acceptMTCPTimestampSQL = `SELECT accepted, gateway, machine_state, node_current
FROM mesh_ops.accept_mtcp_timestamp_v2($1::BYTEA, $2::BYTEA, $3::BIGINT)`

const commitMTCPGatewayTimestampSQL = `SELECT mesh_ops.commit_mtcp_gateway_timestamp_v1($1::BYTEA, $2::BYTEA, $3::BIGINT)`

// Schema 246: a gateway's pod token on every session (K1c-T).
const (
	acceptMTCPTimestampV3SQL = `SELECT accepted, gateway, machine_state, node_current, token_ratcheted
FROM mesh_ops.accept_mtcp_timestamp_v3($1::BYTEA, $2::BYTEA, $3::BIGINT)`
	commitMTCPGatewayTimestampV2SQL = `SELECT result, ratcheted
FROM mesh_ops.commit_mtcp_gateway_timestamp_v2($1::BYTEA, $2::BYTEA, $3::BIGINT, $4::BOOLEAN, $5::TEXT)`
	//nolint:gosec // G101: SQL naming a pod token function, not a credential.
	ratchetKubernetesGatewayTokenSQL = `SELECT mesh_ops.ratchet_kubernetes_gateway_token_v1($1::BYTEA, $2::BYTEA)`
	//nolint:gosec // G101: SQL naming pod token functions, not a credential.
	gatewayTokensGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.commit_mtcp_gateway_timestamp_v2(bytea,bytea,bigint,boolean,text)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.accept_mtcp_timestamp_v3(bytea,bytea,bigint)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.ratchet_kubernetes_gateway_token_v1(bytea,bytea)'), 'EXECUTE'), FALSE)`
)

// Schema 253: an approver suspends a gateway's ratchet for at most a day
// (K1d d2b).
const (
	acceptMTCPTimestampV4SQL = `SELECT accepted, gateway, machine_state, node_current, token_ratcheted, suspended_until
FROM mesh_ops.accept_mtcp_timestamp_v4($1::BYTEA, $2::BYTEA, $3::BIGINT)`
	commitMTCPGatewayTimestampV3SQL = `SELECT result, ratcheted, suspended_until
FROM mesh_ops.commit_mtcp_gateway_timestamp_v3($1::BYTEA, $2::BYTEA, $3::BIGINT, $4::BOOLEAN, $5::TEXT)`
	readGatewayRatchetSuspensionSQL = `SELECT mesh_ops.read_kubernetes_gateway_ratchet_suspension_v1($1::BYTEA, $2::BYTEA)`
	ratchetSuspensionsGrantedSQL    = `SELECT COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.commit_mtcp_gateway_timestamp_v3(bytea,bytea,bigint,boolean,text)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.accept_mtcp_timestamp_v4(bytea,bytea,bigint)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.read_kubernetes_gateway_ratchet_suspension_v1(bytea,bytea)'), 'EXECUTE'), FALSE)`
	// maximumRatchetSuspension bounds what Core reads back (schema 253).
	maximumRatchetSuspension = 24 * time.Hour
)

// MTCPTimestampCheck is what schema 226 says about a handshake's keys.
type MTCPTimestampCheck struct {
	Accepted bool
	// Gateway: the machine key belongs, or belonged, to a Kubernetes
	// gateway; its timestamp was compared, not written.
	Gateway bool
	// MachineState is current, retired or unbound.
	MachineState string
	NodeCurrent  bool
	// TokenRatcheted: the gateway Device holding the machine key proved its
	// pod token on a session before (schema 246; AcceptTimestampV3 only).
	TokenRatcheted bool
	// SuspendedUntil is when the Device's suspended ratchet holds again,
	// zero when it is not suspended (schema 253; AcceptTimestampV4 only).
	SuspendedUntil time.Time
}

// GatewayTimestampCommit is what CommitGatewayTimestampV2 did.
type GatewayTimestampCommit struct {
	Result kubecluster.GatewayTimestampResult
	// Ratcheted: the Device is ratcheted now.
	Ratcheted bool
	// SuspendedUntil is the hard deadline of a session committed without a
	// token because the Device's ratchet is suspended; zero otherwise
	// (schema 253; CommitGatewayTimestampV3 only).
	SuspendedUntil time.Time
}

// ErrMTCPTimestamp classifies an unavailable MTCP timestamp check.
var ErrMTCPTimestamp = errors.New("postgres: MTCP timestamp check unavailable")

// MTCPTimestampStore keeps the last accepted MTCP ClientHello timestamp of
// machine keys bound to an active Device (schema 137).
type MTCPTimestampStore struct {
	database resourceAuthorityDatabase
	metrics  *postgresPoolMetrics
}

// NewMTCPTimestampStore accepts only the runtime-authenticated pool.
func NewMTCPTimestampStore(pool *Pool) (*MTCPTimestampStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil {
		return nil, ErrMTCPTimestamp
	}
	return &MTCPTimestampStore{database: pool.resourceAuthorityDatabase, metrics: pool.metrics}, nil
}

// AcceptTimestamp reports whether timestampMS is newer than the stored one
// for the machine key fingerprint, and what the keys are. Keys without an
// active Device for nodeKey are accepted: the caller's per-replica cache
// decides for them. A gateway's timestamp is compared, not written.
func (store *MTCPTimestampStore) AcceptTimestamp(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
	timestampMS int64,
) (MTCPTimestampCheck, error) {
	if len(nodeKey) != 0 && len(nodeKey) != 32 || timestampMS <= 0 {
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
	var check MTCPTimestampCheck
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, acceptMTCPTimestampSQL, machineFingerprint[:], nodeKey, timestampMS).
			Scan(&check.Accepted, &check.Gateway, &check.MachineState, &check.NodeCurrent)
	})
	if err != nil {
		return MTCPTimestampCheck{}, err
	}
	switch check.MachineState {
	case "current", "retired", "unbound":
		return check, nil
	default:
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
}

// GatewayTokensGranted reports whether the runtime role may use schema
// 246's handshake functions, probed once at startup: Core offers
// gateway.token1 only then.
func (store *MTCPTimestampStore) GatewayTokensGranted(ctx context.Context) (bool, error) {
	var granted bool
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, gatewayTokensGrantedSQL).Scan(&granted)
	})
	return granted, err
}

// AcceptTimestampV3 is AcceptTimestamp with whether the gateway Device
// holding the machine key is ratcheted (schema 246).
func (store *MTCPTimestampStore) AcceptTimestampV3(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64,
) (MTCPTimestampCheck, error) {
	if len(nodeKey) != 0 && len(nodeKey) != 32 || timestampMS <= 0 {
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
	var check MTCPTimestampCheck
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, acceptMTCPTimestampV3SQL, machineFingerprint[:], nodeKey, timestampMS).
			Scan(&check.Accepted, &check.Gateway, &check.MachineState, &check.NodeCurrent, &check.TokenRatcheted)
	})
	if err != nil {
		return MTCPTimestampCheck{}, err
	}
	switch {
	case check.MachineState != "current" && check.MachineState != "retired" && check.MachineState != "unbound",
		check.TokenRatcheted && (!check.Gateway || check.MachineState != "current"):
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
	return check, nil
}

// CommitGatewayTimestampV2 records a gateway's timestamp after its session
// proved its node key, and its ratchet, one Device at a time (schema 246):
// tokenProven is whether the session proved its pod token.
func (store *MTCPTimestampStore) CommitGatewayTimestampV2(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64, tokenProven bool, mode kubecluster.GatewayTokenMode,
) (GatewayTimestampCommit, error) {
	if len(nodeKey) != 32 || timestampMS <= 0 || !mode.IsKnown() {
		return GatewayTimestampCommit{}, ErrMTCPTimestamp
	}
	var commit GatewayTimestampCommit
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, commitMTCPGatewayTimestampV2SQL, machineFingerprint[:], nodeKey,
			timestampMS, tokenProven, string(mode)).Scan(&commit.Result, &commit.Ratcheted)
	})
	if err != nil {
		return GatewayTimestampCommit{}, err
	}
	// A committed proven token always leaves the Device ratcheted.
	if !commit.Result.IsKnown() ||
		commit.Result == kubecluster.GatewayTimestampCommitted && tokenProven && !commit.Ratcheted {
		return GatewayTimestampCommit{}, ErrMTCPTimestamp
	}
	return commit, nil
}

// RatchetSuspensionsGranted reports whether the runtime role may use
// schema 253's handshake functions, probed once at startup: Core honours a
// suspended ratchet only then.
func (store *MTCPTimestampStore) RatchetSuspensionsGranted(ctx context.Context) (bool, error) {
	var granted bool
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, ratchetSuspensionsGrantedSQL).Scan(&granted)
	})
	return granted, err
}

// AcceptTimestampV4 is AcceptTimestampV3 with until when the Device's
// ratchet is suspended (schema 253).
func (store *MTCPTimestampStore) AcceptTimestampV4(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64,
) (MTCPTimestampCheck, error) {
	if len(nodeKey) != 0 && len(nodeKey) != 32 || timestampMS <= 0 {
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
	var check MTCPTimestampCheck
	var until *time.Time
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, acceptMTCPTimestampV4SQL, machineFingerprint[:], nodeKey, timestampMS).
			Scan(&check.Accepted, &check.Gateway, &check.MachineState, &check.NodeCurrent, &check.TokenRatcheted,
				&until)
	})
	if err != nil {
		return MTCPTimestampCheck{}, err
	}
	if until != nil {
		check.SuspendedUntil = until.UTC()
	}
	switch {
	case check.MachineState != "current" && check.MachineState != "retired" && check.MachineState != "unbound",
		check.TokenRatcheted && (!check.Gateway || check.MachineState != "current"),
		!check.SuspendedUntil.IsZero() && !check.TokenRatcheted:
		return MTCPTimestampCheck{}, ErrMTCPTimestamp
	}
	return check, nil
}

// CommitGatewayTimestampV3 is CommitGatewayTimestampV2 honouring a
// suspended ratchet: in mode ratchet a session without a token on a
// suspended Device commits, with the suspension's end as its deadline
// (schema 253).
func (store *MTCPTimestampStore) CommitGatewayTimestampV3(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64, tokenProven bool, mode kubecluster.GatewayTokenMode,
) (GatewayTimestampCommit, error) {
	if len(nodeKey) != 32 || timestampMS <= 0 || !mode.IsKnown() {
		return GatewayTimestampCommit{}, ErrMTCPTimestamp
	}
	var commit GatewayTimestampCommit
	var until *time.Time
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, commitMTCPGatewayTimestampV3SQL, machineFingerprint[:], nodeKey,
			timestampMS, tokenProven, string(mode)).Scan(&commit.Result, &commit.Ratcheted, &until)
	})
	if err != nil {
		return GatewayTimestampCommit{}, err
	}
	if until != nil {
		commit.SuspendedUntil = until.UTC()
	}
	// A deadline comes only with a session committed without a token, in
	// mode ratchet, on a ratcheted Device, and never beyond a day.
	deadline := !commit.SuspendedUntil.IsZero()
	if !commit.Result.IsKnown() ||
		commit.Result == kubecluster.GatewayTimestampCommitted && tokenProven && !commit.Ratcheted ||
		deadline && (commit.Result != kubecluster.GatewayTimestampCommitted || tokenProven || !commit.Ratcheted ||
			mode != kubecluster.GatewayTokenRatchet ||
			commit.SuspendedUntil.After(time.Now().Add(maximumRatchetSuspension+5*time.Minute))) {
		return GatewayTimestampCommit{}, ErrMTCPTimestamp
	}
	return commit, nil
}

// ReadRatchetSuspension reads until when the ratchet of the gateway
// Device holding both keys now is suspended, zero when it is not: what a
// session that relies on a suspension reads again (schema 253).
func (store *MTCPTimestampStore) ReadRatchetSuspension(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte) (time.Time, error) {
	if len(nodeKey) != 32 {
		return time.Time{}, ErrMTCPTimestamp
	}
	var until *time.Time
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, readGatewayRatchetSuspensionSQL, machineFingerprint[:], nodeKey).Scan(&until)
	})
	if err != nil || until == nil {
		return time.Time{}, err
	}
	return until.UTC(), nil
}

// RatchetGatewayToken ratchets the gateway Device holding both keys now,
// for the session that completed its cluster join with a pod token Core
// checked: false when no gateway Device holds them.
func (store *MTCPTimestampStore) RatchetGatewayToken(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte,
) (bool, error) {
	if len(nodeKey) != 32 {
		return false, ErrMTCPTimestamp
	}
	var ratcheted bool
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, ratchetKubernetesGatewayTokenSQL, machineFingerprint[:], nodeKey).
			Scan(&ratcheted)
	})
	return ratcheted, err
}

// CommitGatewayTimestamp records a gateway's timestamp after its session
// proved its node key: false when the keys are no longer the gateway's
// current ones or the timestamp is not newer.
func (store *MTCPTimestampStore) CommitGatewayTimestamp(ctx context.Context, machineFingerprint [32]byte,
	nodeKey []byte, timestampMS int64,
) (bool, error) {
	if len(nodeKey) != 32 || timestampMS <= 0 {
		return false, ErrMTCPTimestamp
	}
	var committed bool
	err := store.run(ctx, func(transaction resourceAuthorityDatabaseTransaction) error {
		return transaction.QueryRow(ctx, commitMTCPGatewayTimestampSQL, machineFingerprint[:], nodeKey,
			timestampMS).Scan(&committed)
	})
	return committed, err
}

func (store *MTCPTimestampStore) run(ctx context.Context,
	statement func(resourceAuthorityDatabaseTransaction) error,
) (resultErr error) {
	if store == nil || store.database == nil || ctx == nil {
		return ErrMTCPTimestamp
	}
	startedAt := time.Now()
	defer func() {
		if store.metrics != nil {
			store.metrics.observeOperation(postgresOperationMTCPTimestamp, time.Since(startedAt), resultErr)
		}
	}()
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return errors.Join(ErrMTCPTimestamp, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if err := statement(transaction); err != nil {
		return errors.Join(ErrMTCPTimestamp, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrMTCPTimestamp, err)
	}
	return nil
}
