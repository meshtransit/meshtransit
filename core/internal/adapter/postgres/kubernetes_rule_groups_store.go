package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

// readPolicyKubernetesGroupsSQL reads the Kubernetes groups of the rules to
// clusters of the release at a policy revision (schema 236).
const readPolicyKubernetesGroupsSQL = `SELECT mesh_ops.read_policy_kubernetes_groups_v1(` +
	sessionArguments + `,$10::UUID,$11::UUID,$12::BIGINT,$13::TIMESTAMPTZ)::TEXT`

var _ compilation.KubernetesRuleGroupReader = (*KubernetesClusterPolicyGroupStore)(nil)

// errInvalidPolicyKubernetesGroups reports a groups read that does not
// decode as the release it names.
var errInvalidPolicyKubernetesGroups = errors.New("postgres: invalid policy Kubernetes groups")

// scannedRow is a row of any transaction kind.
type scannedRow interface{ Scan(...any) error }

// policyKubernetesGroups is a release's rules to clusters, each with its
// groups or nil, and whether the release's hash covers them.
type policyKubernetesGroups struct {
	revision int64
	hashed   bool
	groups   map[policy.RuleID][]string
	clusters map[policy.RuleID]kubecluster.ID
	sources  map[policy.RuleID]publication.RuleSide
}

type policyKubernetesGroupsWire struct {
	Revision int64 `json:"policy_revision"`
	Hashed   bool  `json:"hashed"`
	Rules    []struct {
		ID         string   `json:"id"`
		ClusterID  string   `json:"cluster_id"`
		SourceKind string   `json:"source_kind"`
		SourceID   string   `json:"source_id"`
		Groups     []string `json:"groups"`
	} `json:"rules"`
}

// decodePolicyKubernetesGroups checks the read names the revision asked
// for, each rule once, and groups a rule to a cluster may hold; hashed only
// with some groups.
func decodePolicyKubernetesGroups(encoded []byte, revision int64) (policyKubernetesGroups, bool) {
	var wire policyKubernetesGroupsWire
	if json.Unmarshal(encoded, &wire) != nil || wire.Revision != revision || wire.Rules == nil {
		return policyKubernetesGroups{}, false
	}
	read := policyKubernetesGroups{revision: revision, hashed: wire.Hashed,
		groups:   make(map[policy.RuleID][]string, len(wire.Rules)),
		clusters: make(map[policy.RuleID]kubecluster.ID, len(wire.Rules)),
		sources:  make(map[policy.RuleID]publication.RuleSide, len(wire.Rules))}
	named := false
	for _, rule := range wire.Rules {
		id, err := policy.ParseRuleID(rule.ID)
		cluster, clusterErr := kubecluster.ParseID(rule.ClusterID)
		sourceID, sourceErr := publicid.Parse(rule.SourceID)
		kind, known := sideKinds[rule.SourceKind]
		source, sideErr := publication.NewRuleSide(kind, sourceID)
		if _, seen := read.groups[id]; err != nil || clusterErr != nil || sourceErr != nil || !known ||
			sideErr != nil || seen || !validReadKubernetesGroups(rule.Groups) {
			return policyKubernetesGroups{}, false
		}
		named = named || rule.Groups != nil
		read.groups[id], read.clusters[id], read.sources[id] = rule.Groups, cluster, source
	}
	if read.hashed && !named {
		return policyKubernetesGroups{}, false
	}
	return read, true
}

// sideKinds names a rule source as the groups read writes it.
var sideKinds = map[string]publication.SideKind{
	"device": publication.SideDevice, "device_group": publication.SideDeviceGroup,
	"identity_group": publication.SideIdentityGroup, "device_tag": publication.SideDeviceTag,
}

// validReadKubernetesGroups reports nil, or 1 to 16 sorted distinct groups.
func validReadKubernetesGroups(groups []string) bool {
	if groups == nil {
		return true
	}
	if len(groups) == 0 || len(groups) > kubecluster.MaximumRuleKubernetesGroups {
		return false
	}
	for index, group := range groups {
		if !kubecluster.ValidKubernetesGroup(group) || index > 0 && groups[index-1] >= group {
			return false
		}
	}
	return true
}

// readPolicyKubernetesGroups reads the groups of the release at revision in
// the caller's transaction; found is false when the reader may not see the
// Network's policy or there is no such release.
func readPolicyKubernetesGroups(ctx context.Context, row func(context.Context, string, ...any) scannedRow,
	session accountsession.Session, scope network.Scope, revision int64,
	evaluatedAt time.Time) (read policyKubernetesGroups, found bool, err error) {
	var encoded *string
	if err := row(ctx, readPolicyKubernetesGroupsSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String(), revision, evaluatedAt)...).Scan(&encoded); err != nil {
		return policyKubernetesGroups{}, false, err
	}
	if encoded == nil {
		return policyKubernetesGroups{}, false, nil
	}
	decoded, valid := decodePolicyKubernetesGroups([]byte(*encoded), revision)
	if !valid {
		return policyKubernetesGroups{}, false, errInvalidPolicyKubernetesGroups
	}
	return decoded, true, nil
}

// ReadPolicyKubernetesGroups returns the rules to clusters of the scope's
// release at revision, each with its cluster, source and groups (K1a3).
func (groups *KubernetesClusterPolicyGroupStore) ReadPolicyKubernetesGroups(ctx context.Context,
	session accountsession.Session, scope network.Scope, revision int64) (
	map[policy.RuleID]compilation.ReleasedClusterRule, error) {
	if groups == nil || !session.IsValid() || !scope.IsValid() || revision < 1 {
		return nil, compilation.ErrInvalidRequest
	}
	var held map[policy.RuleID]compilation.ReleasedClusterRule
	err := groups.store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		evaluatedAt, err := readTransactionTime(ctx, tx.QueryRow)
		if err != nil {
			return false, compilation.ErrUnavailable
		}
		read, found, err := readPolicyKubernetesGroups(ctx, func(ctx context.Context, query string,
			arguments ...any) scannedRow {
			return tx.QueryRow(ctx, query, arguments...)
		}, session, scope, revision, evaluatedAt)
		if err != nil {
			return false, compilation.ErrUnavailable
		}
		if !found {
			// The reader may not see the Network's policy, or the release
			// the request replaces is gone: compile nothing on it.
			return false, compilation.ErrForbidden
		}
		held = make(map[policy.RuleID]compilation.ReleasedClusterRule, len(read.groups))
		for id, kubernetesGroups := range read.groups {
			source := read.sources[id]
			held[id] = compilation.ReleasedClusterRule{Cluster: read.clusters[id], SourceKind: source.Kind(),
				SourceID: source.ID(), Groups: kubernetesGroups}
		}
		return false, nil
	})
	if errors.Is(err, compilation.ErrForbidden) {
		return nil, compilation.ErrForbidden
	}
	if err != nil {
		return nil, compilation.ErrUnavailable
	}
	return held, nil
}
