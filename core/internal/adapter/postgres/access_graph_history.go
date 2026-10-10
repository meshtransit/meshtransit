package postgres

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph/ledger"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const readAccessGraphHistorySQL = `SELECT mesh_ops.read_access_graph_history_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::TIMESTAMPTZ,
    $14::UUID, $15::UUID, $16::UUID, $17::TEXT, $18::BYTEA, $19::INTEGER
)::TEXT`

// AccessGraphHistoryStore reads the access edge ledger at one instant.
type AccessGraphHistoryStore struct {
	database resourceAuthorityDatabase
	options  AccountSessionOptions
	metrics  *postgresPoolMetrics
}

var _ ledger.Reader = (*AccessGraphHistoryStore)(nil)

// NewAccessGraphHistoryStore accepts only the runtime-authenticated pool.
func NewAccessGraphHistoryStore(pool *Pool, options AccountSessionOptions) (*AccessGraphHistoryStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, ledger.ErrUnavailable
	}
	return &AccessGraphHistoryStore{database: pool.resourceAuthorityDatabase, options: options, metrics: pool.metrics}, nil
}

// ReadHistory loads one exact-scope page after current policy.read and
// device.read checks.
func (store *AccessGraphHistoryStore) ReadHistory(ctx context.Context, session accountsession.Session,
	scope network.Scope, query ledger.Query, evaluatedAt time.Time,
) (ledger.Result, error) {
	return retryReadConflict(ctx, func() (ledger.Result, error) {
		return store.readOnce(ctx, session, scope, query, evaluatedAt)
	})
}

func optionalNode(id node.ID) any {
	if id == (node.ID{}) {
		return nil
	}
	return id.String()
}

func (store *AccessGraphHistoryStore) readOnce(ctx context.Context, session accountsession.Session,
	scope network.Scope, query ledger.Query, evaluatedAt time.Time,
) (_ ledger.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.metrics != nil {
			store.metrics.observeOperation(postgresOperationAccessGraphHistory, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !scope.IsValid() || query.At.IsZero() || evaluatedAt.IsZero() ||
		query.Limit < 1 || query.Limit > ledger.MaximumPageSize+1 {
		return ledger.Result{}, ledger.ErrInvalidRequest
	}
	// The permission resolver takes FOR SHARE row locks, which need a
	// read-write transaction; the function itself writes nothing.
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil || transaction == nil {
		return ledger.Result{}, errors.Join(ledger.ErrUnavailable, err)
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
		return ledger.Result{}, errors.Join(ledger.ErrUnavailable, err)
	}
	var protocol, after any
	if query.Protocol != policy.ProtocolUnknown {
		protocol = query.Protocol.String()
	}
	if !query.After.IsZero() {
		after = query.After[:]
	}
	var encoded *string
	err = transaction.QueryRow(ctx, readAccessGraphHistorySQL,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt, query.At,
		optionalNode(query.Device), optionalNode(query.Source), optionalNode(query.Destination),
		protocol, after, query.Limit,
	).Scan(&encoded)
	if err != nil {
		return ledger.Result{}, errors.Join(ledger.ErrUnavailable, err)
	}
	if encoded == nil {
		return ledger.Result{}, ledger.ErrForbidden
	}
	result, err := decodeAccessGraphHistory(*encoded, query.Limit)
	if err != nil {
		return ledger.Result{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return ledger.Result{}, errors.Join(ledger.ErrUnavailable, err)
	}
	closed = true
	return result, nil
}

type accessGraphHistoryRecord struct {
	WorkspaceID     string                       `json:"workspace_id"`
	NetworkID       string                       `json:"network_id"`
	At              time.Time                    `json:"at"`
	RecordedSince   *time.Time                   `json:"recorded_since"`
	NetworkRevision *int64                       `json:"network_revision"`
	Snapshot        *accessGraphHistorySnapshot  `json:"snapshot"`
	Edges           []accessGraphHistoryEdgeJSON `json:"edges"`
}

type accessGraphHistorySnapshot struct {
	ID              string    `json:"id"`
	NetworkRevision int64     `json:"network_revision"`
	EffectiveAt     time.Time `json:"effective_at"`
	RecordedAt      time.Time `json:"recorded_at"`
	EdgeCount       int       `json:"edge_count"`
	Digest          string    `json:"digest"`
}

type accessGraphHistoryEdgeJSON struct {
	EdgeID                        string     `json:"edge_id"`
	AccessRuleID                  string     `json:"access_rule_id"`
	SelectorKind                  string     `json:"selector_kind"`
	SourceDeviceID                string     `json:"source_device_id"`
	SourceHostname                *string    `json:"source_hostname"`
	DestinationDeviceID           *string    `json:"destination_device_id"`
	DestinationHostname           *string    `json:"destination_hostname"`
	DestinationImportedResourceID *string    `json:"destination_imported_resource_id"`
	TrustContractID               *string    `json:"trust_contract_id"`
	DestinationResourceID         *string    `json:"destination_resource_id"`
	DestinationResourceGroupID    *string    `json:"destination_resource_group_id"`
	SourceSelectorKind            *string    `json:"source_selector_kind"`
	SourceSelectorID              *string    `json:"source_selector_id"`
	DestinationSelectorKind       *string    `json:"destination_selector_kind"`
	DestinationSelectorID         *string    `json:"destination_selector_id"`
	Protocol                      string     `json:"protocol"`
	PortFirst                     []int      `json:"destination_port_range_first"`
	PortLast                      []int      `json:"destination_port_range_last"`
	ValidFromRevision             int64      `json:"valid_from_revision"`
	ValidFromAt                   time.Time  `json:"valid_from_at"`
	ValidToRevision               *int64     `json:"valid_to_revision"`
	ValidToAt                     *time.Time `json:"valid_to_at"`
	ExpiresAt                     *time.Time `json:"expires_at"`
}

func decodeAccessGraphHistory(encoded string, limit int) (ledger.Result, error) {
	var record accessGraphHistoryRecord
	if err := decodeStrictJSON(encoded, 4*1024*1024, &record); err != nil || record.Edges == nil ||
		len(record.Edges) > limit {
		return ledger.Result{}, ledger.ErrInvalidResult
	}
	workspaceID, workspaceErr := workspace.ParseID(record.WorkspaceID)
	networkID, networkErr := network.ParseID(record.NetworkID)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil {
		return ledger.Result{}, ledger.ErrInvalidResult
	}
	result := ledger.Result{Scope: scope, At: record.At.UTC(), Edges: make([]ledger.Edge, 0, len(record.Edges))}
	if record.RecordedSince != nil {
		result.RecordedSince = record.RecordedSince.UTC()
	}
	if record.NetworkRevision != nil {
		result.NetworkRevision = *record.NetworkRevision
	}
	if snapshot := record.Snapshot; snapshot != nil {
		id, err := publicid.Parse(snapshot.ID)
		if err != nil {
			return ledger.Result{}, ledger.ErrInvalidResult
		}
		result.Snapshot = &ledger.Snapshot{ID: id, NetworkRevision: snapshot.NetworkRevision,
			EffectiveAt: snapshot.EffectiveAt.UTC(), RecordedAt: snapshot.RecordedAt.UTC(),
			EdgeCount: snapshot.EdgeCount, Digest: snapshot.Digest}
	}
	for _, wire := range record.Edges {
		edge, err := decodeAccessGraphHistoryEdge(wire)
		if err != nil {
			return ledger.Result{}, err
		}
		result.Edges = append(result.Edges, edge)
	}
	return result, nil
}

func decodeAccessGraphHistoryEdge(wire accessGraphHistoryEdgeJSON) (ledger.Edge, error) {
	invalid := false
	optionalPublic := func(value *string) publicid.ID {
		if value == nil {
			return publicid.ID{}
		}
		id, err := publicid.Parse(*value)
		invalid = invalid || err != nil
		return id
	}
	text := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	key, keyErr := ledger.ParseEdgeKey(wire.EdgeID)
	rule, ruleErr := publicid.Parse(wire.AccessRuleID)
	source, sourceErr := node.ParseID(wire.SourceDeviceID)
	edge := ledger.Edge{Key: key, AccessRuleID: rule, SelectorKind: wire.SelectorKind, SourceDeviceID: source,
		SourceHostname: text(wire.SourceHostname), DestinationHostname: text(wire.DestinationHostname),
		ImportedResourceID: optionalPublic(wire.DestinationImportedResourceID),
		TrustContractID:    optionalPublic(wire.TrustContractID),
		ResourceID:         optionalPublic(wire.DestinationResourceID),
		ResourceGroupID:    optionalPublic(wire.DestinationResourceGroupID),
		SourceSelectorKind: text(wire.SourceSelectorKind), SourceSelectorID: optionalPublic(wire.SourceSelectorID),
		DestinationSelectorKind: text(wire.DestinationSelectorKind),
		DestinationSelectorID:   optionalPublic(wire.DestinationSelectorID),
		ValidFromRevision:       wire.ValidFromRevision, ValidFrom: wire.ValidFromAt.UTC()}
	if wire.DestinationDeviceID != nil {
		destination, err := node.ParseID(*wire.DestinationDeviceID)
		invalid = invalid || err != nil
		edge.DestinationDeviceID = destination
	}
	switch wire.Protocol {
	case "tcp":
		edge.Protocol = policy.ProtocolTCP
	case "udp":
		edge.Protocol = policy.ProtocolUDP
	case "icmp":
		edge.Protocol = policy.ProtocolICMP
	default:
		invalid = true
	}
	if len(wire.PortFirst) != len(wire.PortLast) || len(wire.PortFirst) > policy.MaximumPortRangesPerRule {
		invalid = true
	}
	for index := range wire.PortFirst {
		first, last := wire.PortFirst[index], wire.PortLast[index]
		if invalid || first < 1 || first > 65535 || last < 1 || last > 65535 {
			invalid = true
			break
		}
		portRange, err := policy.NewPortRange(uint16(first), uint16(last))
		invalid = invalid || err != nil
		edge.Ports = append(edge.Ports, portRange)
	}
	if (wire.ValidToRevision == nil) != (wire.ValidToAt == nil) {
		invalid = true
	} else if wire.ValidToRevision != nil {
		edge.ValidToRevision, edge.ValidTo = *wire.ValidToRevision, wire.ValidToAt.UTC()
	}
	if wire.ExpiresAt != nil {
		edge.ExpiresAt = wire.ExpiresAt.UTC()
	}
	if invalid || keyErr != nil || ruleErr != nil || sourceErr != nil {
		return ledger.Edge{}, ledger.ErrInvalidResult
	}
	return edge, nil
}
