package postgres

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/policydigest"
)

const readDeviceEnforcementHistorySQL = `SELECT mesh_ops.read_device_enforcement_history_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::TIMESTAMPTZ, $14::UUID, $15::INTEGER
)::TEXT`

// DeviceEnforcementHistoryStore reads recorded enforcement evidence at an
// instant (R1-69 increment B).
type DeviceEnforcementHistoryStore struct {
	database resourceAuthorityDatabase
	options  AccountSessionOptions
	metrics  *postgresPoolMetrics
}

var _ enforcementledger.HistoryReader = (*DeviceEnforcementHistoryStore)(nil)

// NewDeviceEnforcementHistoryStore accepts only the runtime-authenticated pool.
func NewDeviceEnforcementHistoryStore(pool *Pool, options AccountSessionOptions) (*DeviceEnforcementHistoryStore,
	error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, enforcementledger.ErrUnavailable
	}
	return &DeviceEnforcementHistoryStore{database: pool.resourceAuthorityDatabase, options: options,
		metrics: pool.metrics}, nil
}

// ReadEnforcementHistory loads one exact-scope page after current device.read checks.
func (store *DeviceEnforcementHistoryStore) ReadEnforcementHistory(ctx context.Context,
	session accountsession.Session, scope network.Scope, at time.Time, after node.ID, limit int,
	evaluatedAt time.Time) (enforcementledger.HistoryResult, error) {
	return retryReadConflict(ctx, func() (enforcementledger.HistoryResult, error) {
		return store.readOnce(ctx, session, scope, at, after, limit, evaluatedAt)
	})
}

func (store *DeviceEnforcementHistoryStore) readOnce(ctx context.Context, session accountsession.Session,
	scope network.Scope, at time.Time, after node.ID, limit int, evaluatedAt time.Time,
) (_ enforcementledger.HistoryResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.metrics != nil {
			store.metrics.observeOperation(postgresOperationEnforcementHistory, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !scope.IsValid() || (!after.IsValid() && after != (node.ID{})) || at.IsZero() ||
		limit < 1 || limit > enforcementledger.MaximumHistoryPageSize+1 || evaluatedAt.IsZero() {
		return enforcementledger.HistoryResult{}, enforcementledger.ErrInvalidRequest
	}
	// The permission resolver takes FOR SHARE row locks, which need a
	// read-write transaction; the function itself writes nothing.
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil || transaction == nil {
		return enforcementledger.HistoryResult{}, errors.Join(enforcementledger.ErrUnavailable, err)
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
		return enforcementledger.HistoryResult{}, errors.Join(enforcementledger.ErrUnavailable, err)
	}
	var afterValue any
	if after.IsValid() {
		afterValue = after.String()
	}
	var encoded *string
	err = transaction.QueryRow(ctx, readDeviceEnforcementHistorySQL,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt, at, afterValue, limit,
	).Scan(&encoded)
	if err != nil {
		return enforcementledger.HistoryResult{}, errors.Join(enforcementledger.ErrUnavailable, err)
	}
	if encoded == nil {
		return enforcementledger.HistoryResult{}, enforcementledger.ErrForbidden
	}
	result, err := decodeDeviceEnforcementHistory(*encoded, limit)
	if err != nil {
		return enforcementledger.HistoryResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return enforcementledger.HistoryResult{}, errors.Join(enforcementledger.ErrUnavailable, err)
	}
	closed = true
	return result, nil
}

type deviceEnforcementHistoryRecord struct {
	WorkspaceID   string                          `json:"workspace_id"`
	NetworkID     string                          `json:"network_id"`
	At            time.Time                       `json:"at"`
	RecordedSince *time.Time                      `json:"recorded_since"`
	Devices       []deviceEnforcementEvidenceJSON `json:"devices"`
}

type deviceEnforcementEvidenceJSON struct {
	ID              string              `json:"id"`
	Hostname        *string             `json:"hostname"`
	State           string              `json:"state"`
	NetworkRevision int64               `json:"network_revision"`
	DeliveredDigest policydigest.Digest `json:"delivered_digest"`
	DeliveredGrants int                 `json:"delivered_grants"`
	EnforcedDigest  policydigest.Digest `json:"enforced_digest"`
	EnforcedGrants  int                 `json:"enforced_grants"`
	AppliedAt       time.Time           `json:"applied_at"`
	ReportedAt      time.Time           `json:"reported_at"`
	ValidFrom       time.Time           `json:"valid_from"`
	ValidTo         *time.Time          `json:"valid_to"`
}

func decodeDeviceEnforcementHistory(encoded string, limit int) (enforcementledger.HistoryResult, error) {
	var record deviceEnforcementHistoryRecord
	if err := decodeStrictJSON(encoded, 1<<20, &record); err != nil || record.Devices == nil ||
		len(record.Devices) > limit {
		return enforcementledger.HistoryResult{}, enforcementledger.ErrInvalidResult
	}
	workspaceID, workspaceErr := workspace.ParseID(record.WorkspaceID)
	networkID, networkErr := network.ParseID(record.NetworkID)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil {
		return enforcementledger.HistoryResult{}, enforcementledger.ErrInvalidResult
	}
	result := enforcementledger.HistoryResult{Scope: scope, At: record.At.UTC(),
		Devices: make([]enforcementledger.Evidence, len(record.Devices))}
	if record.RecordedSince != nil {
		result.RecordedSince = record.RecordedSince.UTC()
	}
	for index, device := range record.Devices {
		id, err := node.ParseID(device.ID)
		if err != nil {
			return enforcementledger.HistoryResult{}, enforcementledger.ErrInvalidResult
		}
		evidence := enforcementledger.Evidence{
			DeviceID: id, State: enforcementledger.State(device.State), NetworkRevision: device.NetworkRevision,
			Delivered: distribution.FilterSummary{Digest: device.DeliveredDigest, Grants: device.DeliveredGrants},
			Enforced:  distribution.FilterSummary{Digest: device.EnforcedDigest, Grants: device.EnforcedGrants},
			AppliedAt: device.AppliedAt.UTC(), ReportedAt: device.ReportedAt.UTC(), ValidFrom: device.ValidFrom.UTC(),
		}
		if device.Hostname != nil {
			evidence.Hostname = *device.Hostname
		}
		if device.ValidTo != nil {
			evidence.ValidTo = device.ValidTo.UTC()
		}
		result.Devices[index] = evidence
	}
	return result, nil
}
