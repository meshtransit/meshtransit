package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Schemas 268 and 269: what the connection log receiver reads (connection
// logs design §16c, §16d). The functions belong to mesh_flowlog_reader, which sees only
// Networks with a destination; this store only ever calls them.
const (
	readFlowlogNetworksSQL = `SELECT pg_catalog.transaction_timestamp(), COALESCE(pg_catalog.jsonb_agg(
    pg_catalog.jsonb_build_object('workspace', listed.workspace_public_id, 'network', listed.network_public_id,
        'enabled', listed.enabled, 'settings_version', listed.settings_version,
        'credential', listed.credential_public_id, 'sealed_version', listed.sealed_version,
        'sealing_key_id', listed.sealing_key_id, 'expected_bucket_owner', listed.expected_bucket_owner,
        'directory_revision', listed.directory_revision)
    ORDER BY listed.network_public_id), '[]'::JSONB)::TEXT
FROM mesh_ops.flowlog_networks_v1($1::UUID, $2::INTEGER) AS listed`
	readFlowlogDestinationSQL = `SELECT pg_catalog.transaction_timestamp(),
    (SELECT pg_catalog.jsonb_build_object('reason', found.reason, 'forwarded', found.forwarded,
        'window_s', found.window_s, 'bucket', found.bucket, 'region', found.region, 'prefix', found.prefix,
        'expected_bucket_owner', found.expected_bucket_owner,
        'settings_version', found.settings_version, 'credential', found.credential_public_id,
        'provider', found.provider, 'account_id', found.account_id,
        'sealed', pg_catalog.encode(found.sealed, 'hex'), 'sealed_version', found.sealed_version,
        'sealing_key_id', found.sealing_key_id)
     FROM mesh_ops.flowlog_destination_v1($1::UUID, $2::UUID) AS found)::TEXT`
	readFlowlogRevocationsSQL = `SELECT pg_catalog.transaction_timestamp(), COALESCE(pg_catalog.jsonb_agg(
    pg_catalog.jsonb_build_object('network', revoked.network_public_id, 'device', revoked.device_public_id,
        'machine_key', pg_catalog.encode(revoked.machine_key, 'hex'))
    ORDER BY revoked.network_public_id, revoked.device_public_id, revoked.machine_key), '[]'::JSONB)::TEXT
FROM mesh_ops.flowlog_revocations_v1(
    pg_catalog.transaction_timestamp() - pg_catalog.make_interval(secs => $1::DOUBLE PRECISION)) AS revoked`

	// maxFlowlogDocument bounds one decoded answer: 100 000 revocations.
	maxFlowlogDocument = 32 << 20
	// maxFlowlogRevocations is the most one answer lists; the function
	// returns one more to tell a full list from a cut one.
	maxFlowlogRevocations = 100000
	// flowlogStatementTimeout bounds every statement of this store (C39).
	flowlogStatementTimeout = "5s"
	configureFlowlogReadSQL = `SELECT pg_catalog.set_config('statement_timeout', $1, TRUE)`
)

var (
	// ErrFlowlogReceiver classifies an unavailable or malformed read.
	ErrFlowlogReceiver = errors.New("postgres: connection log receiver read unavailable")
	// ErrFlowlogRevocationsCut reports more revocations than one answer
	// holds: the receiver must not take a cut list as complete (review
	// s4c1b H2).
	ErrFlowlogRevocationsCut = errors.New("postgres: more connection log revocations than one answer holds")
	// ErrFlowlogNotFound reports no such Network, or no destination.
	ErrFlowlogNotFound = errors.New("postgres: no connection log destination")
)

// FlowlogReceiverStore reads what the connection log receiver needs, on a
// pool of its own so the receiver cannot starve the management API (C39).
type FlowlogReceiverStore struct {
	database resourceAuthorityDatabase
	metrics  *postgresPoolMetrics
}

// NewFlowlogReceiverStore accepts only runtime-authenticated pools: pool,
// the receiver's own, reads; metricsPool, when set, counts the reads with
// the pool metrics Core exports.
func NewFlowlogReceiverStore(pool, metricsPool *Pool) (*FlowlogReceiverStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		(metricsPool != nil && metricsPool.role != PoolRoleRuntime) {
		return nil, ErrFlowlogReceiver
	}
	metrics := pool.metrics
	if metricsPool != nil {
		metrics = metricsPool.metrics
	}
	return &FlowlogReceiverStore{database: pool.resourceAuthorityDatabase, metrics: metrics}, nil
}

// read runs one read-only statement that answers the database time and a
// JSON document.
func (store *FlowlogReceiverStore) read(ctx context.Context, sql string, arguments ...any,
) (_ time.Time, _ *string, resultErr error) {
	if store == nil || store.database == nil || ctx == nil {
		return time.Time{}, nil, ErrFlowlogReceiver
	}
	startedAt := time.Now()
	defer func() {
		if store.metrics != nil {
			store.metrics.observeOperation(postgresOperationFlowlogReceiver, time.Since(startedAt), resultErr)
		}
	}()
	transaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return time.Time{}, nil, errors.Join(ErrFlowlogReceiver, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if err := transaction.Exec(ctx, configureFlowlogReadSQL, flowlogStatementTimeout); err != nil {
		return time.Time{}, nil, errors.Join(ErrFlowlogReceiver, err)
	}
	var at time.Time
	var document *string
	if err := transaction.QueryRow(ctx, sql, arguments...).Scan(&at, &document); err != nil {
		return time.Time{}, nil, errors.Join(ErrFlowlogReceiver, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return time.Time{}, nil, errors.Join(ErrFlowlogReceiver, err)
	}
	if document != nil && len(*document) > maxFlowlogDocument {
		return time.Time{}, nil, ErrFlowlogReceiver
	}
	return at.UTC(), document, nil
}

// Networks lists Networks with a destination after the public ID after
// (the zero ID: from the start), at most limit.
func (store *FlowlogReceiverStore) Networks(ctx context.Context, after network.ID, limit int,
) (connectionlog.ReceiverNetworks, error) {
	if limit < 1 || limit > connectionlog.MaxReceiverNetworks {
		return connectionlog.ReceiverNetworks{}, ErrFlowlogReceiver
	}
	var afterArgument any
	if publicid.ID(after) != (publicid.ID{}) {
		afterArgument = after.String()
	}
	at, document, err := store.read(ctx, readFlowlogNetworksSQL, afterArgument, limit)
	if err != nil {
		return connectionlog.ReceiverNetworks{}, err
	}
	var rows []struct {
		Workspace       string  `json:"workspace"`
		Network         string  `json:"network"`
		Enabled         bool    `json:"enabled"`
		SettingsVersion int64   `json:"settings_version"`
		Credential      string  `json:"credential"`
		SealedVersion   int64   `json:"sealed_version"`
		SealingKeyID    string  `json:"sealing_key_id"`
		BucketOwner     *string `json:"expected_bucket_owner"`
		Revision        int64   `json:"directory_revision"`
	}
	if document == nil || decodeStrictJSON(*document, maxFlowlogDocument, &rows) != nil {
		return connectionlog.ReceiverNetworks{}, ErrFlowlogReceiver
	}
	listed := connectionlog.ReceiverNetworks{
		Networks: make([]connectionlog.ReceiverNetwork, 0, len(rows)), GeneratedAt: at,
	}
	for _, row := range rows {
		workspaceID, workspaceErr := workspace.ParseID(row.Workspace)
		networkID, networkErr := network.ParseID(row.Network)
		credential, credentialErr := publicid.Parse(row.Credential)
		if workspaceErr != nil || networkErr != nil || credentialErr != nil || row.SettingsVersion < 1 ||
			row.SealedVersion < 1 || row.SealingKeyID == "" || row.Revision < 1 {
			return connectionlog.ReceiverNetworks{}, ErrFlowlogReceiver
		}
		entry := connectionlog.ReceiverNetwork{
			Workspace: workspaceID, Network: networkID, Enabled: row.Enabled, SettingsVersion: row.SettingsVersion,
			Credential: connectionlog.CredentialID(credential), SealedVersion: row.SealedVersion,
			SealingKeyID: row.SealingKeyID, DirectoryRevision: row.Revision,
		}
		if row.BucketOwner != nil {
			if !connectionlog.ValidBucketOwner(*row.BucketOwner) {
				return connectionlog.ReceiverNetworks{}, ErrFlowlogReceiver
			}
			entry.ExpectedBucketOwner = *row.BucketOwner
		}
		listed.Networks = append(listed.Networks, entry)
	}
	return listed, nil
}

var receiverReasons = map[string]bool{
	connectionlog.ReasonLogging: false, connectionlog.ReasonDisabled: false,
	connectionlog.ReasonFeatureRevoked: false, connectionlog.ReasonNetworkSuspended: false,
	connectionlog.ReasonWorkspaceSuspended: false, connectionlog.ReasonNetworkDeleted: true,
	connectionlog.ReasonWorkspaceDeleted: true,
}

// Destination reads the exact (Workspace, Network) pair's destination;
// ErrFlowlogNotFound when there is none.
func (store *FlowlogReceiverStore) Destination(ctx context.Context, scope network.Scope,
) (connectionlog.ReceiverDestination, error) {
	if !scope.IsValid() {
		return connectionlog.ReceiverDestination{}, ErrFlowlogReceiver
	}
	at, document, err := store.read(ctx, readFlowlogDestinationSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String())
	if err != nil {
		return connectionlog.ReceiverDestination{}, err
	}
	if document == nil {
		return connectionlog.ReceiverDestination{}, ErrFlowlogNotFound
	}
	var row struct {
		Reason          string  `json:"reason"`
		Forwarded       bool    `json:"forwarded"`
		WindowSeconds   int     `json:"window_s"`
		Bucket          string  `json:"bucket"`
		Region          string  `json:"region"`
		Prefix          string  `json:"prefix"`
		BucketOwner     *string `json:"expected_bucket_owner"`
		SettingsVersion int64   `json:"settings_version"`
		Credential      *string `json:"credential"`
		Provider        *string `json:"provider"`
		AccountID       *string `json:"account_id"`
		Sealed          *string `json:"sealed"`
		SealedVersion   *int64  `json:"sealed_version"`
		SealingKeyID    *string `json:"sealing_key_id"`
	}
	if decodeStrictJSON(*document, maxFlowlogDocument, &row) != nil {
		return connectionlog.ReceiverDestination{}, ErrFlowlogReceiver
	}
	deleted, known := receiverReasons[row.Reason]
	if !known || row.SettingsVersion < 1 {
		return connectionlog.ReceiverDestination{}, ErrFlowlogReceiver
	}
	destination := connectionlog.ReceiverDestination{
		Reason: row.Reason, Forwarded: row.Forwarded, WindowSeconds: row.WindowSeconds, Bucket: row.Bucket,
		Region: row.Region, Prefix: row.Prefix, SettingsVersion: row.SettingsVersion, GeneratedAt: at,
	}
	if row.BucketOwner != nil {
		if !connectionlog.ValidBucketOwner(*row.BucketOwner) {
			return connectionlog.ReceiverDestination{}, ErrFlowlogReceiver
		}
		destination.ExpectedBucketOwner = *row.BucketOwner
	}
	if deleted {
		return destination, nil
	}
	if row.Credential == nil || row.Provider == nil || row.Sealed == nil || row.SealedVersion == nil ||
		row.SealingKeyID == nil {
		return connectionlog.ReceiverDestination{}, ErrFlowlogReceiver
	}
	credential, err := publicid.Parse(*row.Credential)
	sealed, sealedErr := hex.DecodeString(*row.Sealed)
	if err != nil || sealedErr != nil || len(sealed) == 0 || *row.SealedVersion < 1 {
		return connectionlog.ReceiverDestination{}, ErrFlowlogReceiver
	}
	destination.Credential, destination.Provider = connectionlog.CredentialID(credential), *row.Provider
	destination.Sealed, destination.SealedVersion, destination.SealingKeyID = sealed, *row.SealedVersion, *row.SealingKeyID
	if row.AccountID != nil {
		destination.AccountID = *row.AccountID
	}
	return destination, nil
}

// Revocations lists the machine keys revoked within the window.
func (store *FlowlogReceiverStore) Revocations(ctx context.Context) (connectionlog.ReceiverRevocations, error) {
	at, document, err := store.read(ctx, readFlowlogRevocationsSQL,
		connectionlog.ReceiverRevocationWindow.Seconds())
	if err != nil {
		return connectionlog.ReceiverRevocations{}, err
	}
	var rows []struct {
		Network    string `json:"network"`
		Device     string `json:"device"`
		MachineKey string `json:"machine_key"`
	}
	if document == nil || decodeStrictJSON(*document, maxFlowlogDocument, &rows) != nil {
		return connectionlog.ReceiverRevocations{}, ErrFlowlogReceiver
	}
	if len(rows) > maxFlowlogRevocations {
		return connectionlog.ReceiverRevocations{}, errors.Join(ErrFlowlogReceiver, ErrFlowlogRevocationsCut)
	}
	revoked := connectionlog.ReceiverRevocations{
		Revocations: make([]connectionlog.ReceiverRevocation, 0, len(rows)), GeneratedAt: at,
	}
	for _, row := range rows {
		networkID, networkErr := network.ParseID(row.Network)
		device, deviceErr := node.ParseID(row.Device)
		key, keyErr := hex.DecodeString(strings.TrimSpace(row.MachineKey))
		if networkErr != nil || deviceErr != nil || keyErr != nil || len(key) != 32 {
			return connectionlog.ReceiverRevocations{}, ErrFlowlogReceiver
		}
		revoked.Revocations = append(revoked.Revocations, connectionlog.ReceiverRevocation{
			Network: networkID, Device: device, MachineKey: [32]byte(key),
		})
	}
	return revoked, nil
}
