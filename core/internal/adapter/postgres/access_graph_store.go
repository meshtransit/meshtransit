package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/site"
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
// from one repeatable-read, exact-Network transaction, on its database clock.
func (store *AccessGraphStore) ReadActive(
	ctx context.Context,
	session accountsession.Session,
	query accessgraph.Query,
) (snapshot accessgraph.Snapshot, resultErr error) {
	if ctx == nil || !session.IsValid() || !query.IsValid() {
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
	evaluatedAt, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}

	statement, arguments := explainArguments(session, query, evaluatedAt)
	var record accessGraphSnapshotRecord
	var releaseID, targetID *string
	var compilerFormatVersion *int
	var semanticHash []byte
	var paths, explanationContext string
	err = transaction.QueryRow(ctx, statement, arguments...).Scan(
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
		&targetID,
		&paths,
		&explanationContext,
	)
	if err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	record.ReleaseID = releaseID
	record.CompilerFormatVersion = compilerFormatVersion
	record.SemanticHash = semanticHash
	if err := json.Unmarshal([]byte(paths), &record.Paths); err != nil {
		return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
	}
	if record.Context, err = decodeAccessGraphContext(explanationContext); err != nil {
		return accessgraph.Snapshot{}, err
	}
	switch {
	case !query.DestinationAddress().IsValid():
		record.TargetNodeID = targetID
	case record.Context.Target.Kind == accessgraph.TargetKindExitPool.String():
		record.TargetExitPoolID = targetID
	default:
		record.TargetSiteID = targetID
	}
	snapshot, err = record.snapshot(query)
	if err != nil {
		return accessgraph.Snapshot{}, err
	}
	if snapshot, err = nameKubernetesClusterPaths(ctx, transaction.QueryRow, session, query.Scope(),
		snapshot); err != nil {
		return accessgraph.Snapshot{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	committed = true
	return snapshot, nil
}

// explainArguments returns the statement and arguments that explain query:
// explain_address_access_v1 for an address, explain_active_policy_v4
// otherwise.
func explainArguments(session accountsession.Session, query accessgraph.Query, evaluatedAt time.Time,
) (string, []any) {
	arguments := []any{
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		query.Scope().WorkspaceID().String(), query.Scope().NetworkID().String(), query.SourceNodeID().String(),
	}
	if query.DestinationAddress().IsValid() {
		return explainAddressAccessSQL, append(arguments, query.DestinationAddress().String(),
			query.Protocol().String(), int(query.DestinationPort()), evaluatedAt,
			accessgraph.MaximumExplanationPaths+1)
	}
	var destinationNodeArgument, destinationResourceArgument, destinationImportedArgument any
	if query.DestinationNodeID().IsValid() {
		destinationNodeArgument = query.DestinationNodeID().String()
	} else if query.DestinationResourceID().IsValid() {
		destinationResourceArgument = query.DestinationResourceID().String()
	} else {
		destinationImportedArgument = query.DestinationImportedResourceID().String()
	}
	return explainActivePolicySQL, append(arguments, destinationNodeArgument, destinationResourceArgument,
		destinationImportedArgument, query.Protocol().String(), int(query.DestinationPort()), evaluatedAt,
		accessgraph.MaximumExplanationPaths+1)
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
	TargetSiteID          *string
	TargetExitPoolID      *string
	Paths                 []accessGraphPathRecord
	Context               accessGraphContextRecord
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
	// Set only for paths to a shared Device, which carry no destination Device.
	DestinationImportedResourceID string `json:"destination_imported_resource_id"`
	TrustContractID               string `json:"trust_contract_id"`
	// Set only for paths through a group rule (schema 120).
	SourceDeviceGroupID      string `json:"source_device_group_id"`
	DestinationDeviceGroupID string `json:"destination_device_group_id"`
	// Set only for paths through an Identity Group or tag rule (schema 122).
	SourceIdentityGroupID  string `json:"source_identity_group_id"`
	SourceDeviceTagID      string `json:"source_device_tag_id"`
	DestinationDeviceTagID string `json:"destination_device_tag_id"`
	// Set only for paths to a Site (schema 197).
	DestinationSiteID   string   `json:"destination_site_id"`
	DestinationPrefixes []string `json:"destination_prefixes"`
	// Set only for paths to an Exit Pool (schema 206).
	DestinationExitPoolID string `json:"destination_exit_pool_id"`
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
	if record.TargetSiteID != nil {
		targetSiteID, err := site.ParseID(*record.TargetSiteID)
		if err != nil {
			return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
		}
		params.TargetSiteID = targetSiteID
	}
	if record.TargetExitPoolID != nil {
		targetPoolID, err := exitpool.ParseID(*record.TargetExitPoolID)
		if err != nil {
			return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
		}
		params.TargetExitPoolID = targetPoolID
	}
	if err := record.Context.apply(&params); err != nil {
		return accessgraph.Snapshot{}, err
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
	var destinationNodeID node.ID
	var destinationErr error
	if record.DestinationNodeID != "" {
		destinationNodeID, destinationErr = node.ParseID(record.DestinationNodeID)
	}
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
	params := accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID,
		SourceNodeID: sourceNodeID, DestinationNodeID: destinationNodeID,
		Protocol: protocol, DestinationPortRanges: ranges,
		SelectorKind:          parseAccessGraphSelectorKind(record.SelectorKind),
		DestinationResourceID: resourceID, DestinationGroupID: groupID,
	}
	if record.DestinationImportedResourceID != "" || record.TrustContractID != "" {
		importedID, importedErr := sharing.ParseImportedResourceID(record.DestinationImportedResourceID)
		contractID, contractErr := sharing.ParseContractID(record.TrustContractID)
		if importedErr != nil || contractErr != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		params.DestinationImportedResourceID, params.TrustContractID = importedID, contractID
	}
	for _, side := range []struct {
		text   string
		target *devicegroup.ID
	}{{record.SourceDeviceGroupID, &params.SourceDeviceGroupID}, {record.DestinationDeviceGroupID, &params.DestinationDeviceGroupID}} {
		if side.text == "" {
			continue
		}
		parsed, err := devicegroup.ParseID(side.text)
		if err != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		*side.target = parsed
	}
	if record.SourceIdentityGroupID != "" {
		parsed, err := identitygroup.ParseID(record.SourceIdentityGroupID)
		if err != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		params.SourceIdentityGroupID = parsed
	}
	for _, side := range []struct {
		text   string
		target *devicetag.ID
	}{{record.SourceDeviceTagID, &params.SourceTagID}, {record.DestinationDeviceTagID, &params.DestinationTagID}} {
		if side.text == "" {
			continue
		}
		parsed, err := devicetag.ParseID(side.text)
		if err != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		*side.target = parsed
	}
	if err := record.applySite(&params); err != nil {
		return accessgraph.Path{}, err
	}
	if record.DestinationExitPoolID != "" {
		poolID, err := exitpool.ParseID(record.DestinationExitPoolID)
		if err != nil {
			return accessgraph.Path{}, accessgraph.ErrInvalidSnapshot
		}
		params.DestinationExitPoolID = poolID
	}
	return accessgraph.NewPath(params)
}

// applySite parses the Site and granted prefixes of a Site path.
func (record accessGraphPathRecord) applySite(params *accessgraph.PathParams) error {
	if record.DestinationSiteID == "" {
		if len(record.DestinationPrefixes) > 0 {
			return accessgraph.ErrInvalidSnapshot
		}
		return nil
	}
	siteID, err := site.ParseID(record.DestinationSiteID)
	if err != nil || len(record.DestinationPrefixes) > site.MaximumPrefixesPerSite {
		return accessgraph.ErrInvalidSnapshot
	}
	prefixes := make([]netip.Prefix, len(record.DestinationPrefixes))
	for index, text := range record.DestinationPrefixes {
		if prefixes[index], err = netip.ParsePrefix(text); err != nil {
			return accessgraph.ErrInvalidSnapshot
		}
	}
	params.DestinationSiteID, params.DestinationPrefixes = siteID, prefixes
	return nil
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
	case "imported_resource":
		return accessgraph.SelectorKindImportedResource
	case "site":
		return accessgraph.SelectorKindSite
	case "exit_pool":
		return accessgraph.SelectorKindExitPool
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

// nameKubernetesClusterPaths names the cluster on every path through a
// Kubernetes cluster's own Device Group, read in the same snapshot. Paths
// through no Device Group need no read.
func nameKubernetesClusterPaths(ctx context.Context,
	queryRow func(context.Context, string, ...any) resourceAuthorityRow, session accountsession.Session,
	scope network.Scope, snapshot accessgraph.Snapshot) (accessgraph.Snapshot, error) {
	if !slices.ContainsFunc(snapshot.Paths(), func(path accessgraph.Path) bool {
		return path.DestinationDeviceGroupID().IsValid()
	}) {
		return snapshot, nil
	}
	var encoded string
	if err := queryRow(ctx, readKubernetesClusterPolicyGroupsSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String())...).Scan(&encoded); err != nil {
		return accessgraph.Snapshot{}, accessGraphDatabaseError(ctx, err)
	}
	groups, err := decodeKubernetesPolicyGroups(encoded, scope)
	if err != nil {
		return accessgraph.Snapshot{}, accessgraph.ErrInvalidSnapshot
	}
	return snapshot.WithKubernetesClusters(groups)
}
