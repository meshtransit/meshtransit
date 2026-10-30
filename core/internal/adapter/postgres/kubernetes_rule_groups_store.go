package postgres

import (
	"context"
	"encoding/hex"
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
	"meshtransit.net/shared/kubeprofile"
)

// readPolicyKubernetesAccessSQL reads the Kubernetes groups and access
// profiles of the rules to clusters of the release at a policy revision, and
// the release's profiles (schema 259).
const readPolicyKubernetesAccessSQL = `SELECT mesh_ops.read_policy_kubernetes_access_v1(` +
	sessionArguments + `,$10::UUID,$11::UUID,$12::BIGINT,$13::TIMESTAMPTZ)::TEXT`

var _ compilation.KubernetesAccessReader = (*KubernetesClusterPolicyGroupStore)(nil)

// errInvalidPolicyKubernetesGroups reports an access read that does not
// decode as the release it names.
var errInvalidPolicyKubernetesGroups = errors.New("postgres: invalid policy Kubernetes access")

// scannedRow is a row of any transaction kind.
type scannedRow interface{ Scan(...any) error }

// policyKubernetesGroups is a release's rules to clusters, each with its
// groups or nil and its profile or none, the release's profiles, and what
// the release's hash covers of them.
type policyKubernetesGroups struct {
	revision       int64
	hashed         bool
	profilesHashed bool
	groups         map[policy.RuleID][]string
	clusters       map[policy.RuleID]kubecluster.ID
	sources        map[policy.RuleID]publication.RuleSide
	access         map[policy.RuleID]publication.KubernetesAccess
	profiles       []publication.KubernetesProfile
}

type policyKubernetesAccessWire struct {
	Revision       int64 `json:"policy_revision"`
	GroupsHashed   bool  `json:"groups_hashed"`
	ProfilesHashed bool  `json:"profiles_hashed"`
	Rules          []struct {
		ID         string                    `json:"id"`
		ClusterID  string                    `json:"cluster_id"`
		SourceKind string                    `json:"source_kind"`
		SourceID   string                    `json:"source_id"`
		Groups     []string                  `json:"groups"`
		Profile    *policyKubernetesRuleWire `json:"profile"`
	} `json:"rules"`
	Profiles []policyKubernetesProfileWire `json:"profiles"`
}

type policyKubernetesRuleWire struct {
	ID            string   `json:"id"`
	Hash          string   `json:"hash"`
	Namespaces    []string `json:"namespaces"`
	ClusterPart   bool     `json:"cluster_part"`
	Mode          string   `json:"mode"`
	ReportUntilMS *int64   `json:"report_until_ms"`
}

type policyKubernetesProfileWire struct {
	ID          string                 `json:"id"`
	Hash        string                 `json:"hash"`
	Name        string                 `json:"name"`
	Rules       kubernetesProfileRules `json:"rules"`
	Description string                 `json:"description"`
}

// kubernetesProfileRules is how a profile's rules are stored beside its
// name: both parts, as RBAC's PolicyRule.
type kubernetesProfileRules struct {
	Namespaced []kubeprofile.Rule `json:"namespaced,omitempty"`
	Cluster    []kubeprofile.Rule `json:"cluster,omitempty"`
}

// decodePolicyKubernetesGroups checks the read names the revision asked
// for, each rule once, groups a rule to a cluster may hold, and a profile
// only with groups and of the release; each profile once, its content that
// of its hash. Hashed only with some groups, profiles hashed only with some
// profile.
func decodePolicyKubernetesGroups(encoded []byte, revision int64) (policyKubernetesGroups, bool) {
	var wire policyKubernetesAccessWire
	if json.Unmarshal(encoded, &wire) != nil || wire.Revision != revision || wire.Rules == nil ||
		wire.Profiles == nil || len(wire.Profiles) > publication.MaximumKubernetesProfiles {
		return policyKubernetesGroups{}, false
	}
	read := policyKubernetesGroups{revision: revision, hashed: wire.GroupsHashed, profilesHashed: wire.ProfilesHashed,
		groups:   make(map[policy.RuleID][]string, len(wire.Rules)),
		clusters: make(map[policy.RuleID]kubecluster.ID, len(wire.Rules)),
		sources:  make(map[policy.RuleID]publication.RuleSide, len(wire.Rules)),
		access:   make(map[policy.RuleID]publication.KubernetesAccess, len(wire.Rules)),
		profiles: make([]publication.KubernetesProfile, 0, len(wire.Profiles))}
	held := make(map[publication.KubernetesProfileID][32]byte, len(wire.Profiles))
	for _, entry := range wire.Profiles {
		profile, valid := decodePolicyKubernetesProfile(entry)
		if _, seen := held[profile.ID()]; !valid || seen {
			return policyKubernetesGroups{}, false
		}
		held[profile.ID()] = profile.ContentHash()
		read.profiles = append(read.profiles, profile)
	}
	named, profiled := false, false
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
		if rule.Profile == nil {
			continue
		}
		access, valid := decodePolicyKubernetesRuleAccess(*rule.Profile)
		if hash, found := held[access.ProfileID()]; !valid || rule.Groups == nil || !found ||
			hash != access.ProfileHash() {
			return policyKubernetesGroups{}, false
		}
		read.access[id], profiled = access, true
	}
	if read.hashed && !named || read.profilesHashed && (!profiled || !read.hashed) {
		return policyKubernetesGroups{}, false
	}
	return read, true
}

// decodePolicyKubernetesProfile checks a stored profile against the hash
// it is stored under.
func decodePolicyKubernetesProfile(entry policyKubernetesProfileWire) (publication.KubernetesProfile, bool) {
	id, err := publication.ParseKubernetesProfileID(entry.ID)
	if err != nil {
		return publication.KubernetesProfile{}, false
	}
	profile, err := publication.NewKubernetesProfile(publication.KubernetesProfileParams{ID: id,
		Description: entry.Description, Profile: kubeprofile.Profile{Name: entry.Name,
			Namespaced: entry.Rules.Namespaced, Cluster: entry.Rules.Cluster}})
	hash := profile.ContentHash()
	if err != nil || entry.Hash != hex.EncodeToString(hash[:]) {
		return publication.KubernetesProfile{}, false
	}
	return profile, true
}

// decodePolicyKubernetesRuleAccess reads a rule's profile: enforcing, or
// reporting until a deadline.
func decodePolicyKubernetesRuleAccess(wire policyKubernetesRuleWire) (publication.KubernetesAccess, bool) {
	id, err := publication.ParseKubernetesProfileID(wire.ID)
	decoded, hashErr := hex.DecodeString(wire.Hash)
	if err != nil || hashErr != nil || len(decoded) != 32 {
		return publication.KubernetesAccess{}, false
	}
	params := publication.KubernetesAccessParams{ProfileID: id, ProfileHash: [32]byte(decoded),
		Namespaces: wire.Namespaces, ClusterPart: wire.ClusterPart}
	switch {
	case wire.Mode == "enforce" && wire.ReportUntilMS == nil:
	case wire.Mode == "report" && wire.ReportUntilMS != nil && *wire.ReportUntilMS > 0:
		params.Report, params.ReportUntil = true, time.UnixMilli(*wire.ReportUntilMS).UTC()
	default:
		return publication.KubernetesAccess{}, false
	}
	access, err := publication.NewKubernetesAccess(params)
	return access, err == nil
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

// readPolicyKubernetesGroups reads the groups and profiles of the release at
// revision in the caller's transaction; found is false when the reader may
// not see the Network's policy or there is no such release.
func readPolicyKubernetesGroups(ctx context.Context, row func(context.Context, string, ...any) scannedRow,
	session accountsession.Session, scope network.Scope, revision int64,
	evaluatedAt time.Time) (read policyKubernetesGroups, found bool, err error) {
	var encoded *string
	if err := row(ctx, readPolicyKubernetesAccessSQL, append(sessionQueryArguments(session),
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

// ReadPolicyKubernetesAccess returns the rules to clusters of the scope's
// release at revision, each with its cluster, source, groups and profile, and
// the release's profiles (K1a3, K2).
func (groups *KubernetesClusterPolicyGroupStore) ReadPolicyKubernetesAccess(ctx context.Context,
	session accountsession.Session, scope network.Scope, revision int64) (
	compilation.ReleasedKubernetesAccess, error) {
	if groups == nil || !session.IsValid() || !scope.IsValid() || revision < 1 {
		return compilation.ReleasedKubernetesAccess{}, compilation.ErrInvalidRequest
	}
	var released compilation.ReleasedKubernetesAccess
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
		released = compilation.ReleasedKubernetesAccess{
			Rules:    make(map[policy.RuleID]compilation.ReleasedClusterRule, len(read.groups)),
			Profiles: read.profiles,
		}
		for id, kubernetesGroups := range read.groups {
			source := read.sources[id]
			released.Rules[id] = compilation.ReleasedClusterRule{Cluster: read.clusters[id],
				SourceKind: source.Kind(), SourceID: source.ID(), Groups: kubernetesGroups, Access: read.access[id]}
		}
		return false, nil
	})
	if errors.Is(err, compilation.ErrForbidden) {
		return compilation.ReleasedKubernetesAccess{}, compilation.ErrForbidden
	}
	if err != nil {
		return compilation.ReleasedKubernetesAccess{}, compilation.ErrUnavailable
	}
	return released, nil
}
