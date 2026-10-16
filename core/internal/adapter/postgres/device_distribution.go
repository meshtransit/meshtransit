package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/workspace"
)

// readDeviceDistributionSQL reads the current revisions and one Device
// (schema 177).
const readDeviceDistributionSQL = `SELECT mesh_ops.read_device_distribution_target_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::UUID
)::TEXT`

// DeviceDistributionStore reads the durable side of policy distribution
// status: current revisions and the Devices that should hold them.
type DeviceDistributionStore struct {
	database resourceAuthorityDatabase
	options  AccountSessionOptions
	metrics  *postgresPoolMetrics
}

var _ distribution.Reader = (*DeviceDistributionStore)(nil)

// NewDeviceDistributionStore accepts only the runtime-authenticated pool.
func NewDeviceDistributionStore(pool *Pool, options AccountSessionOptions) (*DeviceDistributionStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, distribution.ErrUnavailable
	}
	return &DeviceDistributionStore{database: pool.resourceAuthorityDatabase, options: options, metrics: pool.metrics}, nil
}

// ReadTarget loads the current revisions and one Device of the scope after
// current device.read checks on the database clock.
func (store *DeviceDistributionStore) ReadTarget(ctx context.Context, session accountsession.Session,
	scope network.Scope, id node.ID,
) (distribution.Target, error) {
	return retryReadConflict(ctx, func() (distribution.Target, error) {
		return store.readOnce(ctx, session, scope, id)
	})
}

func (store *DeviceDistributionStore) readOnce(ctx context.Context, session accountsession.Session,
	scope network.Scope, id node.ID,
) (_ distribution.Target, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.metrics != nil {
			store.metrics.observeOperation(postgresOperationDeviceDistribution, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return distribution.Target{}, distribution.ErrInvalidRequest
	}
	// The permission resolver takes FOR SHARE row locks, which need a
	// read-write transaction; the function itself writes nothing.
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil || transaction == nil {
		return distribution.Target{}, errors.Join(distribution.ErrUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureAccountSessionReadTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return distribution.Target{}, errors.Join(distribution.ErrUnavailable, err)
	}
	evaluatedAt, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return distribution.Target{}, errors.Join(distribution.ErrUnavailable, err)
	}
	var encoded *string
	err = transaction.QueryRow(ctx, readDeviceDistributionSQL,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt, id.String(),
	).Scan(&encoded)
	if err != nil {
		return distribution.Target{}, errors.Join(distribution.ErrUnavailable, err)
	}
	if encoded == nil {
		return distribution.Target{}, distribution.ErrForbidden
	}
	target, err := decodeDeviceDistribution(*encoded)
	if err != nil {
		return distribution.Target{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return distribution.Target{}, errors.Join(distribution.ErrUnavailable, err)
	}
	closed = true
	return target, nil
}

type deviceDistributionRecord struct {
	WorkspaceID     string                         `json:"workspace_id"`
	NetworkID       string                         `json:"network_id"`
	NetworkRevision int64                          `json:"network_revision"`
	PolicyRevision  int64                          `json:"policy_revision"`
	Devices         []deviceDistributionDeviceJSON `json:"devices"`
}

type deviceDistributionDeviceJSON struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	State    string `json:"state"`
}

func decodeDeviceDistribution(encoded string) (distribution.Target, error) {
	if len(encoded) > 1024*1024 {
		return distribution.Target{}, distribution.ErrInvalidResult
	}
	var record deviceDistributionRecord
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || record.Devices == nil || len(record.Devices) > 1 {
		return distribution.Target{}, distribution.ErrInvalidResult
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return distribution.Target{}, distribution.ErrInvalidResult
	}
	workspaceID, workspaceErr := workspace.ParseID(record.WorkspaceID)
	networkID, networkErr := network.ParseID(record.NetworkID)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil {
		return distribution.Target{}, distribution.ErrInvalidResult
	}
	target := distribution.Target{Scope: scope, NetworkRevision: record.NetworkRevision,
		PolicyRevision: record.PolicyRevision, Devices: make([]distribution.TargetDevice, len(record.Devices))}
	for index, device := range record.Devices {
		id, err := node.ParseID(device.ID)
		if err != nil {
			return distribution.Target{}, distribution.ErrInvalidResult
		}
		target.Devices[index] = distribution.TargetDevice{ID: id, Hostname: device.Hostname, State: device.State}
	}
	return target, nil
}
