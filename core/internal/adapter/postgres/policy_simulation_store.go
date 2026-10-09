package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/core/internal/domain/devicegroup"
	"github.com/meshtransit/meshtransit/core/internal/domain/devicetag"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identitygroup"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

const maximumPolicySimulationBaselineRules = policy.MaximumRules + 1

// PolicySimulationOptions bounds one authorized baseline transaction.
type PolicySimulationOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// PolicySimulationStore reconstructs complete active policy evidence through the runtime role.
type PolicySimulationStore struct {
	database resourceAuthorityDatabase
	options  PolicySimulationOptions
}

var _ simulation.BaselineReader = (*PolicySimulationStore)(nil)

// NewPolicySimulationStore constructs an exact-scope Policy simulation baseline reader.
func NewPolicySimulationStore(
	pool *Pool,
	options PolicySimulationOptions,
) (*PolicySimulationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		!validPolicySimulationOptions(options) {
		return nil, simulation.ErrUnavailable
	}
	return &PolicySimulationStore{
		database: pool.resourceAuthorityDatabase,
		options:  options,
	}, nil
}

func validPolicySimulationOptions(options PolicySimulationOptions) bool {
	return validAccessGraphOptions(AccessGraphOptions(options))
}

// ReadSimulationBaseline freshly authorizes policy.validate and reconstructs the
// current complete compiled artifact inside one repeatable-read transaction,
// rerun on a fresh snapshot when a concurrent publish holds the revision row.
func (store *PolicySimulationStore) ReadSimulationBaseline(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	evaluatedAt time.Time,
) (simulation.Baseline, error) {
	return retryReadConflict(ctx, func() (simulation.Baseline, error) {
		return store.readSimulationBaselineOnce(ctx, session, scope, evaluatedAt)
	})
}

func (store *PolicySimulationStore) readSimulationBaselineOnce(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	evaluatedAt time.Time,
) (baseline simulation.Baseline, resultErr error) {
	if ctx == nil || !session.IsValid() || !scope.IsValid() || evaluatedAt.IsZero() {
		return simulation.Baseline{}, simulation.ErrInvalidRequest
	}
	if store == nil || store.database == nil || !validPolicySimulationOptions(store.options) {
		return simulation.Baseline{}, simulation.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return simulation.Baseline{}, errors.Join(simulation.ErrUnavailable, err)
	}
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return simulation.Baseline{}, policySimulationDatabaseError(ctx, err)
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
		return simulation.Baseline{}, policySimulationDatabaseError(ctx, err)
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(
		ctx,
		setResourceAuthorityScopeSQL,
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return simulation.Baseline{}, policySimulationDatabaseError(ctx, err)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return simulation.Baseline{}, simulation.ErrUnavailable
	}

	var record policySimulationBaselineRecord
	var releaseID *string
	var compilerFormatVersion *int
	var rules, groupRules, groupMembers string
	err = transaction.QueryRow(
		ctx,
		readPolicySimulationBaselineSQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
		evaluatedAt.UTC(),
		maximumPolicySimulationBaselineRules,
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
		&record.SemanticHash,
		&rules,
		&groupRules,
		&groupMembers,
	)
	if err != nil {
		return simulation.Baseline{}, policySimulationDatabaseError(ctx, err)
	}
	record.ReleaseID = releaseID
	record.CompilerFormatVersion = compilerFormatVersion
	if err := json.Unmarshal([]byte(rules), &record.Rules); err != nil {
		return simulation.Baseline{}, simulation.ErrInvalidBaseline
	}
	if err := json.Unmarshal([]byte(groupRules), &record.GroupRules); err != nil ||
		len(record.GroupRules) > policy.MaximumRules {
		return simulation.Baseline{}, simulation.ErrInvalidBaseline
	}
	if err := json.Unmarshal([]byte(groupMembers), &record.SelectorMembers); err != nil {
		return simulation.Baseline{}, simulation.ErrInvalidBaseline
	}
	baseline, err = record.baseline(scope)
	if err != nil {
		return simulation.Baseline{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return simulation.Baseline{}, policySimulationDatabaseError(ctx, err)
	}
	committed = true
	return baseline, nil
}

type policySimulationBaselineRecord struct {
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
	Rules                 []policyPublicationRulePayload
	GroupRules            []policyGroupRulePayload
	SelectorMembers       []struct {
		Kind       string   `json:"kind"`
		SelectorID string   `json:"selector_id"`
		DeviceIDs  []string `json:"device_ids"`
	}
}

var selectorKinds = map[string]publication.SideKind{
	"device_group": publication.SideDeviceGroup, "identity_group": publication.SideIdentityGroup,
	"device_tag": publication.SideDeviceTag,
}

func (record policySimulationBaselineRecord) selectorMembers() (map[publication.RuleSide][]node.ID, error) {
	members := make(map[publication.RuleSide][]node.ID, len(record.SelectorMembers))
	for _, item := range record.SelectorMembers {
		kind, known := selectorKinds[item.Kind]
		id, err := publicid.Parse(item.SelectorID)
		if !known || err != nil || item.DeviceIDs == nil {
			return nil, simulation.ErrInvalidBaseline
		}
		side, err := publication.NewRuleSide(kind, id)
		if err != nil {
			return nil, simulation.ErrInvalidBaseline
		}
		if _, duplicate := members[side]; duplicate {
			return nil, simulation.ErrInvalidBaseline
		}
		devices := make([]node.ID, len(item.DeviceIDs))
		for index, text := range item.DeviceIDs {
			if devices[index], err = node.ParseID(text); err != nil {
				return nil, simulation.ErrInvalidBaseline
			}
		}
		members[side] = devices
	}
	return members, nil
}

// decodePolicyGroupRules rebuilds group rules from the attach payload shape.
func decodePolicyGroupRules(payloads []policyGroupRulePayload) ([]publication.GroupRule, error) {
	rules := make([]publication.GroupRule, 0, len(payloads))
	for _, payload := range payloads {
		ruleID, err := policy.ParseRuleID(payload.AccessRulePublicID)
		if err != nil || len(payload.PortRangeFirst) != len(payload.PortRangeLast) {
			return nil, simulation.ErrInvalidBaseline
		}
		params := publication.GroupRuleParams{RuleID: ruleID, Protocol: parsePolicyRuleProtocol(payload.Protocol)}
		parse := func(text string, target *node.ID) error {
			if text == "" {
				return nil
			}
			value, parseErr := node.ParseID(text)
			*target = value
			return parseErr
		}
		parseGroup := func(text string, target *devicegroup.ID) error {
			if text == "" {
				return nil
			}
			value, parseErr := devicegroup.ParseID(text)
			*target = value
			return parseErr
		}
		parseIdentity := func(text string, target *identitygroup.ID) error {
			if text == "" {
				return nil
			}
			value, parseErr := identitygroup.ParseID(text)
			*target = value
			return parseErr
		}
		parseTag := func(text string, target *devicetag.ID) error {
			if text == "" {
				return nil
			}
			value, parseErr := devicetag.ParseID(text)
			*target = value
			return parseErr
		}
		if errors.Join(parse(payload.SourceNodePublicID, &params.SourceNodeID),
			parseGroup(payload.SourceDeviceGroupPublicID, &params.SourceGroupID),
			parseIdentity(payload.SourceIdentityGroupPublicID, &params.SourceIdentityGroupID),
			parseTag(payload.SourceDeviceTagPublicID, &params.SourceTagID),
			parse(payload.DestinationNodePublicID, &params.DestinationNodeID),
			parseGroup(payload.DestinationDeviceGroupPublicID, &params.DestinationGroupID),
			parseTag(payload.DestinationDeviceTagPublicID, &params.DestinationTagID)) != nil {
			return nil, simulation.ErrInvalidBaseline
		}
		for index := range payload.PortRangeFirst {
			first, last := payload.PortRangeFirst[index], payload.PortRangeLast[index]
			if first < 1 || first > 65535 || last < first || last > 65535 {
				return nil, simulation.ErrInvalidBaseline
			}
			// Both bounds were checked to lie in 1..65535 above.
			portRange, rangeErr := policy.NewPortRange(uint16(first), uint16(last)) //nolint:gosec // bounded above
			if rangeErr != nil {
				return nil, simulation.ErrInvalidBaseline
			}
			params.DestinationPortRanges = append(params.DestinationPortRanges, portRange)
		}
		rule, err := publication.NewGroupRule(params)
		if err != nil {
			return nil, simulation.ErrInvalidBaseline
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parsePolicyRuleProtocol(value string) policy.Protocol {
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

func (record policySimulationBaselineRecord) baseline(
	scope network.Scope,
) (simulation.Baseline, error) {
	vector, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: record.NetworkRevision, InventoryRevision: record.InventoryRevision,
		GroupRevision: record.GroupRevision, PolicyRevision: record.PolicyRevision,
		DNSRevision: record.DNSRevision, RouteRevision: record.RouteRevision,
		SharingRevision: record.SharingRevision, IsolationGeneration: record.IsolationGeneration,
	})
	if err != nil || len(record.Rules) > policy.MaximumRules {
		return simulation.Baseline{}, simulation.ErrInvalidBaseline
	}
	if !record.HasActiveRelease {
		if record.ReleaseID != nil || record.CompilerFormatVersion != nil ||
			len(record.SemanticHash) != 0 || len(record.Rules) != 0 {
			return simulation.Baseline{}, simulation.ErrInvalidBaseline
		}
		snapshot, snapshotErr := policy.NewSnapshot(policy.SnapshotParams{
			Scope: scope, Revision: vector.PolicyRevision(), Rules: []policy.Rule{},
		})
		if snapshotErr != nil {
			return simulation.Baseline{}, simulation.ErrInvalidBaseline
		}
		candidate, candidateErr := publication.NewCandidate(snapshot, 1)
		members, membersErr := record.selectorMembers()
		if candidateErr != nil || membersErr != nil || len(record.GroupRules) != 0 {
			return simulation.Baseline{}, simulation.ErrInvalidBaseline
		}
		return simulation.NewBaseline(simulation.BaselineParams{
			Scope: scope, RevisionVector: vector, Candidate: candidate, SelectorMembers: members,
		})
	}
	if record.ReleaseID == nil || record.CompilerFormatVersion == nil ||
		len(record.SemanticHash) != 32 {
		return simulation.Baseline{}, simulation.ErrInvalidBaseline
	}
	releaseID, err := publication.ParseReleaseID(*record.ReleaseID)
	if err != nil {
		return simulation.Baseline{}, simulation.ErrInvalidBaseline
	}
	var hashValue [32]byte
	copy(hashValue[:], record.SemanticHash)
	semanticHash, err := publication.NewSemanticHash(hashValue)
	if err != nil {
		return simulation.Baseline{}, simulation.ErrInvalidBaseline
	}
	candidate, err := reconstructPolicySimulationCandidate(
		scope,
		vector.PolicyRevision(),
		*record.CompilerFormatVersion,
		record.Rules,
	)
	if err != nil {
		return simulation.Baseline{}, fmt.Errorf("reconstruct compiled baseline: %w", err)
	}
	if len(record.GroupRules) > 0 {
		groupRules, groupErr := decodePolicyGroupRules(record.GroupRules)
		if groupErr != nil {
			return simulation.Baseline{}, groupErr
		}
		if candidate, err = candidate.WithGroupRules(groupRules); err != nil {
			return simulation.Baseline{}, fmt.Errorf("reconstruct group rules: %w", simulation.ErrInvalidBaseline)
		}
	}
	members, err := record.selectorMembers()
	if err != nil {
		return simulation.Baseline{}, err
	}
	if candidate.SemanticHash() != semanticHash {
		return simulation.Baseline{}, fmt.Errorf("compiled baseline semantic hash differs: %w", simulation.ErrInvalidBaseline)
	}
	return simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: vector, HasActiveRelease: true,
		ReleaseID: releaseID, SemanticHash: semanticHash, Candidate: candidate, SelectorMembers: members,
	})
}

type policySimulationGroupEvidence struct {
	groupID           resource.GroupID
	groupVersion      int64
	definitionVersion int64
	groupRevision     int64
	semanticHash      resource.SemanticHash
}

type policySimulationGroupBuilder struct {
	ruleID   policy.RuleID
	evidence policySimulationGroupEvidence
	members  []publication.ResourceGroupMemberDestination
}

func reconstructPolicySimulationCandidate(
	scope network.Scope,
	revision int64,
	compilerFormatVersion int,
	records []policyPublicationRulePayload,
) (publication.Candidate, error) {
	rules := make([]policy.Rule, 0, len(records))
	directDestinations := make([]publication.ResourceDestination, 0, len(records))
	groupBuilders := make(map[policy.RuleID]*policySimulationGroupBuilder)
	importedDestinations := make(
		[]publication.ImportedResourceDestination,
		0,
		len(records),
	)
	for _, record := range records {
		importedPresent := policySimulationImportedEvidencePresent(record)
		directPresent := policySimulationDirectEvidencePresent(record)
		groupPresent := policySimulationGroupEvidencePresent(record)
		if importedPresent {
			if directPresent || groupPresent || record.DestinationNodePublicID != "" {
				return publication.Candidate{}, simulation.ErrInvalidBaseline
			}
			destination, destinationErr := policySimulationImportedDestination(scope, record)
			if destinationErr != nil {
				return publication.Candidate{}, destinationErr
			}
			importedDestinations = append(importedDestinations, destination)
			continue
		}
		rule, err := policySimulationRule(scope, record)
		if err != nil {
			return publication.Candidate{}, simulation.ErrInvalidBaseline
		}
		rules = append(rules, rule)
		if directPresent && groupPresent {
			return publication.Candidate{}, simulation.ErrInvalidBaseline
		}
		if directPresent {
			destination, destinationErr := policySimulationDirectDestination(scope, rule, record)
			if destinationErr != nil {
				return publication.Candidate{}, simulation.ErrInvalidBaseline
			}
			directDestinations = append(directDestinations, destination)
		}
		if groupPresent {
			if err := appendPolicySimulationGroupMember(scope, rule, record, groupBuilders); err != nil {
				return publication.Candidate{}, simulation.ErrInvalidBaseline
			}
		}
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: revision, Rules: rules,
	})
	if err != nil {
		return publication.Candidate{}, simulation.ErrInvalidBaseline
	}
	groupDestinations := make([]publication.ResourceGroupDestination, 0, len(groupBuilders))
	for _, builder := range groupBuilders {
		destination, destinationErr := publication.NewResourceGroupDestination(
			publication.ResourceGroupDestinationParams{
				RuleID: builder.ruleID, Scope: scope,
				ResourceGroupID:   builder.evidence.groupID,
				GroupVersion:      builder.evidence.groupVersion,
				DefinitionVersion: builder.evidence.definitionVersion,
				GroupRevision:     builder.evidence.groupRevision,
				GroupSemanticHash: builder.evidence.semanticHash,
				Members:           builder.members,
			},
		)
		if destinationErr != nil {
			return publication.Candidate{}, simulation.ErrInvalidBaseline
		}
		groupDestinations = append(groupDestinations, destination)
	}
	switch {
	case len(importedDestinations) > 0 && compilerFormatVersion == 4:
		return publication.NewCandidateWithImportedResourceDestinations(
			snapshot,
			directDestinations,
			groupDestinations,
			importedDestinations,
		)
	case len(groupDestinations) > 0 && compilerFormatVersion == 3:
		return publication.NewCandidateWithResourceGroupDestinations(
			snapshot,
			directDestinations,
			groupDestinations,
		)
	case len(groupDestinations) == 0 && len(directDestinations) > 0 && compilerFormatVersion == 2:
		return publication.NewCandidateWithResourceDestinations(snapshot, directDestinations)
	case len(groupDestinations) == 0 && len(directDestinations) == 0 && compilerFormatVersion == 1:
		return publication.NewCandidate(snapshot, compilerFormatVersion)
	default:
		return publication.Candidate{}, simulation.ErrInvalidBaseline
	}
}

func policySimulationImportedEvidencePresent(record policyPublicationRulePayload) bool {
	return record.DestinationImportedResourcePublicID != "" ||
		record.DestinationImportedResourceVersion != 0 ||
		record.DestinationTrustContractPublicID != "" ||
		record.DestinationTrustContractVersion != 0 ||
		record.DestinationShareOfferPublicID != "" ||
		record.DestinationResourceExportPublicID != "" ||
		record.DestinationResourceExportVersion != 0 ||
		record.DestinationProviderWorkspacePublicID != "" ||
		record.DestinationProviderNetworkPublicID != "" ||
		record.DestinationProviderResourcePublicID != "" ||
		record.DestinationProviderResourceVersion != 0 ||
		record.DestinationProviderTargetGeneration != 0 ||
		record.DestinationProviderResourceSemanticHash != "" ||
		record.DestinationProviderInventoryRevision != 0 ||
		record.DestinationProviderSharingRevision != 0 ||
		record.DestinationConsumerSharingRevision != 0 ||
		record.DestinationProviderAuthorityGeneration != 0 ||
		record.DestinationConsumerAuthorityGeneration != 0 ||
		record.DestinationRecoveryEpoch != 0 ||
		record.DestinationContractExpiresAt != "" ||
		record.DestinationConstraintHash != "" ||
		record.DestinationAuthorityEvaluatedAt != "" ||
		len(record.DestinationContractConstraints) != 0
}

func policySimulationImportedDestination(
	scope network.Scope,
	record policyPublicationRulePayload,
) (publication.ImportedResourceDestination, error) {
	if _, err := publication.ParseProjectionID(record.ProjectionPublicID); err != nil ||
		len(record.PortRangeFirst) != len(record.PortRangeLast) {
		return publication.ImportedResourceDestination{}, simulation.ErrInvalidBaseline
	}
	ruleID, ruleErr := policy.ParseRuleID(record.AccessRulePublicID)
	sourceID, sourceErr := node.ParseID(record.SourceNodePublicID)
	protocol := parseAccessGraphProtocol(record.Protocol)
	ranges, rangeErr := policySimulationPortRanges(
		record.PortRangeFirst,
		record.PortRangeLast,
		protocol,
	)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, record.DestinationContractExpiresAt)
	evaluatedAt, evaluatedErr := time.Parse(
		time.RFC3339Nano,
		record.DestinationAuthorityEvaluatedAt,
	)
	if ruleErr != nil || sourceErr != nil || !protocol.IsValid() || rangeErr != nil ||
		expiresErr != nil || evaluatedErr != nil {
		return publication.ImportedResourceDestination{}, fmt.Errorf("decode imported baseline rule: %w", simulation.ErrInvalidBaseline)
	}
	resolution, err := (importedPolicyDestinationRecord{
		ImportedResourceID:          record.DestinationImportedResourcePublicID,
		ImportedResourceVersion:     record.DestinationImportedResourceVersion,
		ContractID:                  record.DestinationTrustContractPublicID,
		ContractVersion:             record.DestinationTrustContractVersion,
		OfferID:                     record.DestinationShareOfferPublicID,
		ExportID:                    record.DestinationResourceExportPublicID,
		ExportVersion:               record.DestinationResourceExportVersion,
		ProviderWorkspaceID:         record.DestinationProviderWorkspacePublicID,
		ProviderNetworkID:           record.DestinationProviderNetworkPublicID,
		ConsumerWorkspaceID:         scope.WorkspaceID().String(),
		ConsumerNetworkID:           scope.NetworkID().String(),
		ResourceID:                  record.DestinationProviderResourcePublicID,
		ResourceVersion:             record.DestinationProviderResourceVersion,
		TargetGeneration:            record.DestinationProviderTargetGeneration,
		ResourceSemanticHash:        record.DestinationProviderResourceSemanticHash,
		ProviderInventoryRevision:   record.DestinationProviderInventoryRevision,
		ProviderSharingRevision:     record.DestinationProviderSharingRevision,
		ConsumerSharingRevision:     record.DestinationConsumerSharingRevision,
		ProviderAuthorityGeneration: record.DestinationProviderAuthorityGeneration,
		ConsumerAuthorityGeneration: record.DestinationConsumerAuthorityGeneration,
		RecoveryEpoch:               record.DestinationRecoveryEpoch,
		ExpiresAt:                   expiresAt,
		ConstraintHash:              record.DestinationConstraintHash,
		Constraints:                 record.DestinationContractConstraints,
	}).value(evaluatedAt, scope)
	if err != nil {
		return publication.ImportedResourceDestination{}, fmt.Errorf("decode imported baseline authority: %w", simulation.ErrInvalidBaseline)
	}
	requestedConstraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: protocol, DestinationPortRanges: ranges,
	})
	if err != nil {
		return publication.ImportedResourceDestination{}, simulation.ErrInvalidBaseline
	}
	requestedTraffic, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{requestedConstraint})
	if err != nil || !requestedTraffic.IsSubsetOf(resolution.Contract().MaximumTraffic()) {
		return publication.ImportedResourceDestination{}, fmt.Errorf("imported baseline traffic exceeds authority: %w", simulation.ErrInvalidBaseline)
	}
	destination, err := publication.NewImportedResourceDestination(
		publication.ImportedResourceDestinationParams{
			RuleID: ruleID, SourceNodeID: sourceID, Resolution: resolution,
			Protocol: protocol, DestinationPortRanges: ranges,
		},
	)
	if err != nil {
		return publication.ImportedResourceDestination{}, simulation.ErrInvalidBaseline
	}
	return destination, nil
}

func policySimulationPortRanges(
	firstValues []int,
	lastValues []int,
	protocol policy.Protocol,
) ([]policy.PortRange, error) {
	if len(firstValues) != len(lastValues) || len(firstValues) > policy.MaximumPortRangesPerRule ||
		protocol == policy.ProtocolICMP && len(firstValues) != 0 ||
		protocol != policy.ProtocolICMP && len(firstValues) == 0 {
		return nil, simulation.ErrInvalidBaseline
	}
	ranges := make([]policy.PortRange, len(firstValues))
	for index, first := range firstValues {
		last := lastValues[index]
		if first < 1 || first > 65535 || last < first || last > 65535 {
			return nil, simulation.ErrInvalidBaseline
		}
		// #nosec G115 -- both values are range-checked against uint16's positive domain above.
		value, err := policy.NewPortRange(uint16(first), uint16(last))
		if err != nil {
			return nil, simulation.ErrInvalidBaseline
		}
		ranges[index] = value
	}
	return ranges, nil
}

func policySimulationRule(
	scope network.Scope,
	record policyPublicationRulePayload,
) (policy.Rule, error) {
	if _, err := publication.ParseProjectionID(record.ProjectionPublicID); err != nil ||
		len(record.PortRangeFirst) != len(record.PortRangeLast) {
		return policy.Rule{}, simulation.ErrInvalidBaseline
	}
	ruleID, ruleErr := policy.ParseRuleID(record.AccessRulePublicID)
	sourceID, sourceErr := node.ParseID(record.SourceNodePublicID)
	destinationID, destinationErr := node.ParseID(record.DestinationNodePublicID)
	protocol := parseAccessGraphProtocol(record.Protocol)
	if ruleErr != nil || sourceErr != nil || destinationErr != nil || !protocol.IsValid() {
		return policy.Rule{}, simulation.ErrInvalidBaseline
	}
	ranges := make([]policy.PortRange, len(record.PortRangeFirst))
	for index, first := range record.PortRangeFirst {
		last := record.PortRangeLast[index]
		if first < 1 || first > 65535 || last < 1 || last > 65535 {
			return policy.Rule{}, simulation.ErrInvalidBaseline
		}
		value, err := policy.NewPortRange(uint16(first), uint16(last))
		if err != nil {
			return policy.Rule{}, simulation.ErrInvalidBaseline
		}
		ranges[index] = value
	}
	return policy.NewRule(policy.RuleParams{
		ID: ruleID, Scope: scope, SourceNodeID: sourceID, DestinationNodeID: destinationID,
		Protocol: protocol, DestinationPortRanges: ranges,
	})
}

func policySimulationDirectEvidencePresent(record policyPublicationRulePayload) bool {
	return record.DestinationResourcePublicID != "" || record.DestinationResourceVersion != 0 ||
		record.DestinationTargetGeneration != 0 || record.DestinationInventoryRevision != 0 ||
		record.DestinationResourceSemanticHash != ""
}

func policySimulationGroupEvidencePresent(record policyPublicationRulePayload) bool {
	return record.DestinationResourceGroupPublicID != "" ||
		record.DestinationResourceGroupVersion != 0 ||
		record.DestinationGroupDefinitionVersion != 0 || record.DestinationGroupRevision != 0 ||
		record.DestinationResourceGroupSemanticHash != "" ||
		record.DestinationGroupMemberResourcePublicID != "" ||
		record.DestinationGroupMemberResourceVersion != 0 ||
		record.DestinationGroupMemberTargetGeneration != 0 ||
		record.DestinationGroupMemberInventoryRevision != 0 ||
		record.DestinationGroupMemberResourceSemanticHash != ""
}

func policySimulationDirectDestination(
	scope network.Scope,
	rule policy.Rule,
	record policyPublicationRulePayload,
) (publication.ResourceDestination, error) {
	resourceID, idErr := resource.ParseID(record.DestinationResourcePublicID)
	semanticHash, hashErr := parsePolicySimulationResourceHash(
		record.DestinationResourceSemanticHash,
	)
	if idErr != nil || hashErr != nil {
		return publication.ResourceDestination{}, simulation.ErrInvalidBaseline
	}
	return publication.NewResourceDestination(publication.ResourceDestinationParams{
		RuleID: rule.ID(), Scope: scope, ResourceID: resourceID,
		ResourceVersion:   record.DestinationResourceVersion,
		TargetGeneration:  record.DestinationTargetGeneration,
		InventoryRevision: record.DestinationInventoryRevision,
		DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: semanticHash,
	})
}

func appendPolicySimulationGroupMember(
	scope network.Scope,
	rule policy.Rule,
	record policyPublicationRulePayload,
	builders map[policy.RuleID]*policySimulationGroupBuilder,
) error {
	groupID, groupErr := resource.ParseGroupID(record.DestinationResourceGroupPublicID)
	groupHash, groupHashErr := parsePolicySimulationResourceHash(
		record.DestinationResourceGroupSemanticHash,
	)
	memberID, memberErr := resource.ParseID(record.DestinationGroupMemberResourcePublicID)
	memberHash, memberHashErr := parsePolicySimulationResourceHash(
		record.DestinationGroupMemberResourceSemanticHash,
	)
	if groupErr != nil || groupHashErr != nil || memberErr != nil || memberHashErr != nil {
		return simulation.ErrInvalidBaseline
	}
	evidence := policySimulationGroupEvidence{
		groupID: groupID, groupVersion: record.DestinationResourceGroupVersion,
		definitionVersion: record.DestinationGroupDefinitionVersion,
		groupRevision:     record.DestinationGroupRevision, semanticHash: groupHash,
	}
	builder, found := builders[rule.ID()]
	if !found {
		builder = &policySimulationGroupBuilder{ruleID: rule.ID(), evidence: evidence}
		builders[rule.ID()] = builder
	} else if builder.evidence != evidence {
		return simulation.ErrInvalidBaseline
	}
	member, err := publication.NewResourceGroupMemberDestination(
		publication.ResourceGroupMemberDestinationParams{
			Scope: scope, ResourceID: memberID,
			ResourceVersion:   record.DestinationGroupMemberResourceVersion,
			TargetGeneration:  record.DestinationGroupMemberTargetGeneration,
			InventoryRevision: record.DestinationGroupMemberInventoryRevision,
			DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: memberHash,
		},
	)
	if err != nil {
		return simulation.ErrInvalidBaseline
	}
	builder.members = append(builder.members, member)
	return nil
}

func parsePolicySimulationResourceHash(value string) (resource.SemanticHash, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return resource.SemanticHash{}, simulation.ErrInvalidBaseline
	}
	var hashValue [32]byte
	copy(hashValue[:], decoded)
	hash, err := resource.NewSemanticHash(hashValue)
	if err != nil {
		return resource.SemanticHash{}, simulation.ErrInvalidBaseline
	}
	return hash, nil
}

func policySimulationDatabaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(simulation.ErrUnavailable, ctx.Err())
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "42501" {
		return simulation.ErrForbidden
	}
	if errors.As(err, &databaseError) && databaseError.Code == "MTD07" {
		return simulation.ErrTooLarge
	}
	return errors.Join(simulation.ErrUnavailable, fmt.Errorf("read policy simulation baseline: %w", err))
}
