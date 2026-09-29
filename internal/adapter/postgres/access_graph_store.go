package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
)

// AccessGraphOptions bounds one effective-policy explanation transaction.
type AccessGraphOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// AccessGraphStore reads revision-bound effective policy through the runtime role.
type AccessGraphStore struct {
	database resourceAuthorityDatabase
	options  AccessGraphOptions
}

var _ accessgraph.Reader = (*AccessGraphStore)(nil)

// NewAccessGraphStore constructs an exact-scope Access Graph reader.
func NewAccessGraphStore(pool *Pool, options AccessGraphOptions) (*AccessGraphStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		!validAccessGraphOptions(options) {
		return nil, accessgraph.ErrUnavailable
	}
	return &AccessGraphStore{database: pool.resourceAuthorityDatabase, options: options}, nil
}

func validAccessGraphOptions(options AccessGraphOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maximumResourceAuthorityStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maximumResourceAuthorityLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maximumResourceAuthorityIdleTimeout
}

// ReadActive authorizes policy.explain and reads the matching active compiled paths
// from one repeatable-read, exact-Network transaction.
func (store *AccessGraphStore) ReadActive(
	ctx context.Context,
	session accountsession.Session,
	query accessgraph.Query,
	evaluatedAt time.Time,
) (snapshot accessgraph.Snapshot, resultErr error) {
	if ctx == nil || !session.IsValid() || !query.IsValid() || evaluatedAt.IsZero() {
		return accessgraph.Snapshot{}, accessgraph.ErrInvalidQuery
	}
	if store == nil || store.database == nil || !validAccessGraphOptions(store.options) {
		return accessgraph.Snapshot{}, accessgraph.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return accessgraph.Snapshot{}, errors.Join(accessgraph.ErrUnavailable, err)
	}
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	if err := transaction.Exec(
		ctx,
		configureResourceAuthoritySQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(
		ctx,
		setResourceAuthorityScopeSQL,
		query.Scope().WorkspaceID().String(),
		query.Scope().NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return accessgraph.Snapshot{}, accessgraph.ErrUnavailable
	}

	var destinationNodeArgument, destinationResourceArgument, destinationImportedArgument any
	if query.DestinationNodeID().IsValid() {
		destinationNodeArgument = query.DestinationNodeID().String()
	} else if query.DestinationResourceID().IsValid() {
		destinationResourceArgument = query.DestinationResourceID().String()
	} else {
		destinationImportedArgument = query.DestinationImportedResourceID().String()
	}
	var record accessGraphSnapshotRecord
	var releaseID, targetNodeID *string
	var compilerFormatVersion *int
	var semanticHash []byte
	var paths string
	err = transaction.QueryRow(
		ctx,
		explainActivePolicySQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		query.Scope().WorkspaceID().String(),
		query.Scope().NetworkID().String(),
		query.SourceNodeID().String(),
		destinationNodeArgument,
		destinationResourceArgument,
		destinationImportedArgument,
		query.Protocol().String(),
		int(query.DestinationPort()),
		evaluatedAt,
		accessgraph.MaximumExplanationPaths+1,
	).Scan(
		&record.NetworkRevision,
		&record.InventoryRevision,
		&record.GroupRevision,
		&record.PolicyRevision,
		&record.DNSRevision,
		&record.RouteRevision,
		&record.SharingRevision,
		&record.IsolationGeneration,
		&record.HasActiveRelease,
		&releaseID,
		&compilerFormatVersion,
		&semanticHash,
		&targetNodeID,
		&paths,
	)
	if err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	record.ReleaseID = releaseID
	record.CompilerFormatVersion = compilerFormatVersion
	record.SemanticHash = semanticHash
	record.TargetNodeID = targetNodeID
	if err := json.Unmarshal([]byte(paths), &record.Paths); err != nil {
		return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
	}
	snapshot, err = record.snapshot(query)
	if err != nil {
		return accessgraph.Snapshot{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	committed = true
	return snapshot, nil
}

type accessGraphSnapshotRecord struct {
	NetworkRevision       int64
	InventoryRevision     int64
	GroupRevision         int64
	PolicyRevision        int64
	DNSRevision           int64
	RouteRevision         int64
	SharingRevision       int64
	IsolationGeneration   int64
	HasActiveRelease      bool
	ReleaseID             *string
	CompilerFormatVersion *int
	SemanticHash          []byte
	TargetNodeID          *string
	Paths                 []accessGraphPathRecord
}

type accessGraphPathRecord struct {
	ProjectionID              string `json:"projection_id"`
	RuleID                    string `json:"access_rule_id"`
	SourceNodeID              string `json:"source_device_id"`
	DestinationNodeID         string `json:"destination_device_id"`
	Protocol                  string `json:"protocol"`
	DestinationPortRangeFirst []int  `json:"destination_port_range_first"`
	DestinationPortRangeLast  []int  `json:"destination_port_range_last"`
	SelectorKind              string `json:"selector_kind"`
	DestinationResourceID     string `json:"destination_resource_id"`
	DestinationGroupID        string `json:"destination_resource_group_id"`
}

func (record accessGraphSnapshotRecord) snapshot(query accessgraph.Query) (accessgraph.Snapshot, error) {
	params := accessgraph.SnapshotParams{
		Scope: query.Scope(), NetworkRevision: record.NetworkRevision,
		InventoryRevision: record.InventoryRevision, GroupRevision: record.GroupRevision,
		PolicyRevision: record.PolicyRevision, DNSRevision: record.DNSRevision,
		RouteRevision: record.RouteRevision, SharingRevision: record.SharingRevision,
		IsolationGeneration: record.IsolationGeneration, HasActiveRelease: record.HasActiveRelease,
	}
	if record.HasActiveRelease {
		if record.ReleaseID == nil || record.CompilerFormatVersion == nil || len(record.SemanticHash) != 32 {
			return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
		}
		releaseID, err := publication.ParseReleaseID(*record.ReleaseID)
		if err != nil {
			return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
		}
		var hashValue [32]byte
		copy(hashValue[:], record.SemanticHash)
		hash, err := publication.NewSemanticHash(hashValue)
		if err != nil {
			return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
		}
		params.ReleaseID = releaseID
		params.CompilerFormatVersion = *record.CompilerFormatVersion
		params.SemanticHash = hash
	} else if record.ReleaseID != nil || record.CompilerFormatVersion != nil || len(record.SemanticHash) != 0 {
		return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
	}
	if record.TargetNodeID != nil {
		targetNodeID, err := node.ParseID(*record.TargetNodeID)
		if err != nil {
			return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
		}
		params.TargetNodeID = targetNodeID
	}
	params.Paths = make([]accessgraph.Path, len(record.Paths))
	for index, pathRecord := range record.Paths {
		path, err := pathRecord.path()
		if err != nil {
			return accessgraph.Snapshot{}, err
		}
		params.Paths[index] = path
	}
	return accessgraph.NewSnapshot(params)
}

func (record accessGraphPathRecord) path() (accessgraph.Path, error) {
	projectionID, projectionErr := publication.ParseProjectionID(record.ProjectionID)
	ruleID, ruleErr := policy.ParseRuleID(record.RuleID)
	sourceNodeID, sourceErr := node.ParseID(record.SourceNodeID)
	destinationNodeID, destinationErr := node.ParseID(record.DestinationNodeID)
	protocol := parseAccessGraphProtocol(record.Protocol)
	if projectionErr != nil || ruleErr != nil || sourceErr != nil || destinationErr != nil ||
		!protocol.IsValid() || len(record.DestinationPortRangeFirst) != len(record.DestinationPortRangeLast) {
		return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
	}
	ranges := make([]policy.PortRange, len(record.DestinationPortRangeFirst))
	for index, first := range record.DestinationPortRangeFirst {
		last := record.DestinationPortRangeLast[index]
		if first < 1 || first > 65535 || last < 1 || last > 65535 {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		value, err := policy.NewPortRange(uint16(first), uint16(last))
		if err != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		ranges[index] = value
	}
	var resourceID resource.ID
	if record.DestinationResourceID != "" {
		parsed, err := resource.ParseID(record.DestinationResourceID)
		if err != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		resourceID = parsed
	}
	var groupID resource.GroupID
	if record.DestinationGroupID != "" {
		parsed, err := resource.ParseGroupID(record.DestinationGroupID)
		if err != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		groupID = parsed
	}
	return accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID,
		SourceNodeID: sourceNodeID, DestinationNodeID: destinationNodeID,
		Protocol: protocol, DestinationPortRanges: ranges,
		SelectorKind:          parseAccessGraphSelectorKind(record.SelectorKind),
		DestinationResourceID: resourceID, DestinationGroupID: groupID,
	})
}

func parseAccessGraphProtocol(value string) policy.Protocol {
	switch value {
	case "tcp":
		return policy.ProtocolTCP
	case "udp":
		return policy.ProtocolUDP
	case "icmp":
		return policy.ProtocolICMP
	default:
		return policy.ProtocolUnknown
	}
}

func parseAccessGraphSelectorKind(value string) accessgraph.SelectorKind {
	switch value {
	case "device":
		return accessgraph.SelectorKindDevice
	case "resource":
		return accessgraph.SelectorKindResource
	case "resource_group":
		return accessgraph.SelectorKindResourceGroup
	default:
		return accessgraph.SelectorKindUnknown
	}
}

func accessGraphDatabaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(accessgraph.ErrUnavailable, ctx.Err())
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "42501" {
		return accessgraph.ErrForbidden
	}
	return errors.Join(accessgraph.ErrUnavailable, fmt.Errorf("read active policy explanation: %w", err))
}
