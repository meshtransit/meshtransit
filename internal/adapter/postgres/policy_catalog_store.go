package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/catalog"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// Reuse the parameterized read plan without caching authority or rule data.
const configureActivePolicyReadTransactionSQL = configureResourceAuthoritySQL + `,
    pg_catalog.set_config('plan_cache_mode', 'force_generic_plan', TRUE)`

const readActivePolicySQL = `SELECT mesh_ops.read_active_policy_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT,
    $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ
)::TEXT`

// ActivePolicyStore reads consumer-local rule projections under current policy.read.
type ActivePolicyStore struct {
	database resourceAuthorityDatabase
	options  PolicySimulationOptions
	metrics  *postgresPoolMetrics
}

// NewActivePolicyStore accepts only a runtime-authenticated pool and bounded timeouts.
func NewActivePolicyStore(pool *Pool, options PolicySimulationOptions) (*ActivePolicyStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil || !validPolicySimulationOptions(options) {
		return nil, simulation.ErrUnavailable
	}
	return &ActivePolicyStore{database: pool.resourceAuthorityDatabase, options: options, metrics: pool.metrics}, nil
}

// ReadActivePolicy rechecks session generations and exact-scope policy.read with
// authorization and revision locks in one bounded repeatable-read transaction,
// rerun on a fresh snapshot when a concurrent publish holds the revision row.
func (store *ActivePolicyStore) ReadActivePolicy(ctx context.Context, session accountsession.Session, scope network.Scope, evaluatedAt time.Time) (catalog.Snapshot, error) {
	return retryReadConflict(ctx, func() (catalog.Snapshot, error) {
		return store.readActivePolicyOnce(ctx, session, scope, evaluatedAt)
	})
}

func (store *ActivePolicyStore) readActivePolicyOnce(ctx context.Context, session accountsession.Session, scope network.Scope, evaluatedAt time.Time) (_ catalog.Snapshot, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.metrics != nil {
			store.metrics.observeOperation(postgresOperationActivePolicyRead, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || !session.IsValid() || !scope.IsValid() || evaluatedAt.IsZero() {
		return catalog.Snapshot{}, simulation.ErrInvalidRequest
	}
	if store == nil || store.database == nil || !validPolicySimulationOptions(store.options) {
		return catalog.Snapshot{}, simulation.ErrUnavailable
	}
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil || transaction == nil {
		return catalog.Snapshot{}, policySimulationDatabaseError(ctx, errors.Join(err, simulation.ErrUnavailable))
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureActivePolicyReadTransactionSQL, postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.LockTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return catalog.Snapshot{}, policySimulationDatabaseError(ctx, err)
	}
	var ws, net int64
	if err := transaction.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(), scope.NetworkID().String()).Scan(&ws, &net); err != nil {
		return catalog.Snapshot{}, policySimulationDatabaseError(ctx, err)
	}
	if ws < 1 || net < 1 {
		return catalog.Snapshot{}, simulation.ErrForbidden
	}
	var encoded *string
	err = transaction.QueryRow(ctx, readActivePolicySQL, session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(), session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(), session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(), scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt.UTC()).Scan(&encoded)
	if err != nil {
		return catalog.Snapshot{}, policySimulationDatabaseError(ctx, err)
	}
	if encoded == nil {
		return catalog.Snapshot{}, simulation.ErrForbidden
	}
	snapshot, err := decodeActivePolicy(*encoded)
	if err != nil || snapshot.Scope() != scope {
		return catalog.Snapshot{}, simulation.ErrInvalidBaseline
	}
	if err := transaction.Commit(ctx); err != nil {
		return catalog.Snapshot{}, policySimulationDatabaseError(ctx, err)
	}
	committed = true
	return snapshot, nil
}

type activePolicyWire struct {
	WorkspaceID     string                 `json:"workspace_id"`
	NetworkID       string                 `json:"network_id"`
	Revision        int64                  `json:"policy_revision"`
	SemanticHash    *string                `json:"semantic_hash"`
	RuleCount       int                    `json:"rule_count"`
	DeviceRulesOnly bool                   `json:"device_rules_only"`
	Rules           []activePolicyRuleWire `json:"rules"`
}
type activePolicyRuleWire struct {
	ID            string `json:"id"`
	SourceID      string `json:"source_device_id"`
	DestinationID string `json:"destination_device_id"`
	Protocol      string `json:"protocol"`
	SelectorKind  string `json:"selector_kind"`
	SelectorID    string `json:"destination_selector_id"`
	Ports         []struct {
		First int `json:"first"`
		Last  int `json:"last"`
	} `json:"destination_port_ranges"`
}

func decodeActivePolicy(encoded string) (catalog.Snapshot, error) {
	if len(encoded) > 1024*1024 {
		return catalog.Snapshot{}, simulation.ErrInvalidBaseline
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire activePolicyWire
	if decoder.Decode(&wire) != nil || wire.Rules == nil || len(wire.Rules) > catalog.MaximumRows {
		return catalog.Snapshot{}, simulation.ErrInvalidBaseline
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return catalog.Snapshot{}, simulation.ErrInvalidBaseline
	}
	ws, wsErr := workspace.ParseID(wire.WorkspaceID)
	net, netErr := network.ParseID(wire.NetworkID)
	scope, err := network.NewScope(ws, net)
	if wsErr != nil || netErr != nil || err != nil {
		return catalog.Snapshot{}, simulation.ErrInvalidBaseline
	}
	rows := make([]catalog.Row, 0, len(wire.Rules))
	for _, row := range wire.Rules {
		parsed, rowErr := row.parse(scope)
		if rowErr != nil {
			return catalog.Snapshot{}, simulation.ErrInvalidBaseline
		}
		rows = append(rows, parsed)
	}
	var hash publication.SemanticHash
	if wire.SemanticHash == nil && wire.Revision == 1 && wire.RuleCount == 0 {
		empty, emptyErr := policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: 1, Rules: []policy.Rule{}})
		candidate, candidateErr := publication.NewCandidate(empty, 1)
		if emptyErr != nil || candidateErr != nil {
			return catalog.Snapshot{}, simulation.ErrInvalidBaseline
		}
		hash = candidate.SemanticHash()
	} else if wire.SemanticHash != nil {
		decoded, decodeErr := hex.DecodeString(*wire.SemanticHash)
		if decodeErr != nil || len(decoded) != 32 {
			return catalog.Snapshot{}, simulation.ErrInvalidBaseline
		}
		var value [32]byte
		copy(value[:], decoded)
		hash, err = publication.NewSemanticHash(value)
		if err != nil {
			return catalog.Snapshot{}, simulation.ErrInvalidBaseline
		}
	}
	return catalog.NewSnapshot(catalog.SnapshotParams{Scope: scope, Revision: wire.Revision, SemanticHash: hash, RuleCount: wire.RuleCount, DeviceRulesOnly: wire.DeviceRulesOnly, Rows: rows})
}

func (row activePolicyRuleWire) parse(scope network.Scope) (catalog.Row, error) {
	id, err := policy.ParseRuleID(row.ID)
	source, sourceErr := node.ParseID(row.SourceID)
	protocol := map[string]policy.Protocol{"tcp": policy.ProtocolTCP, "udp": policy.ProtocolUDP, "icmp": policy.ProtocolICMP}[row.Protocol]
	if err != nil || sourceErr != nil || !protocol.IsValid() || row.Ports == nil || len(row.Ports) > 64 {
		return catalog.Row{}, catalog.ErrInvalidSnapshot
	}
	params := compilation.RuleIntentParams{ID: id, Scope: scope, SourceNodeID: source, Protocol: protocol, DestinationPortRanges: make([]policy.PortRange, 0, len(row.Ports))}
	for _, port := range row.Ports {
		if port.First < 1 || port.First > 65535 || port.Last < 1 || port.Last > 65535 || port.First > port.Last {
			return catalog.Row{}, catalog.ErrInvalidSnapshot
		}
		parsed, portErr := policy.NewPortRange(uint16(port.First), uint16(port.Last))
		if portErr != nil {
			return catalog.Row{}, portErr
		}
		params.DestinationPortRanges = append(params.DestinationPortRanges, parsed)
	}
	var destination node.ID
	if row.DestinationID != "" {
		destination, err = node.ParseID(row.DestinationID)
		if err != nil {
			return catalog.Row{}, err
		}
	}
	switch row.SelectorKind {
	case "device":
		params.DestinationNodeID, err = node.ParseID(row.SelectorID)
	case "resource":
		params.DestinationResourceID, err = resource.ParseID(row.SelectorID)
	case "resource_group":
		params.DestinationGroupID, err = resource.ParseGroupID(row.SelectorID)
	case "imported_resource":
		params.DestinationImportedResourceID, err = sharing.ParseImportedResourceID(row.SelectorID)
	default:
		return catalog.Row{}, catalog.ErrInvalidSnapshot
	}
	if err != nil {
		return catalog.Row{}, err
	}
	intent, err := compilation.NewRuleIntent(params)
	return catalog.Row{Intent: intent, DestinationNodeID: destination}, err
}
