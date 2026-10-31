package publication

import (
	"bytes"
	"errors"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubeprofile"
)

// Bounds of Kubernetes access profiles in a release (K2 §7.4, §21).
const (
	// MaximumKubernetesProfiles bounds the permission sets one release holds
	// once they belong to clusters (K2h Q267).
	MaximumKubernetesProfiles = 1024
	// MaximumSharedKubernetesProfiles bounds them while a Core that does not
	// know clusters may still publish: it refuses more (K2h §32.12 M-6).
	MaximumSharedKubernetesProfiles = 256
	// MaximumKubernetesProfileDescription bounds a description, in characters.
	MaximumKubernetesProfileDescription = 512
	// MaximumKubernetesReport bounds how long a rule may report instead of
	// enforce, from its release.
	MaximumKubernetesReport = 14 * 24 * time.Hour
	// MaximumClusterKubernetesGrantKeys bounds the distinct grant keys
	// (group, scope, mode, report deadline) the rules to one cluster make,
	// so that no peer ever holds more than a gateway takes, whatever the
	// membership becomes after the release.
	MaximumClusterKubernetesGrantKeys = 64
	// MaximumClusterKubernetesProfiles bounds the profiles of one cluster's
	// scope table.
	MaximumClusterKubernetesProfiles = 128
	// MaximumClusterKubernetesScopes bounds the scopes of one cluster's
	// scope table.
	MaximumClusterKubernetesScopes = 256
	// MaximumClusterScopeTableBytes bounds the encoded scope table of one
	// cluster, less room for the cluster's access contact (field 3, at most
	// 256 bytes).
	MaximumClusterScopeTableBytes = 256<<10 - 1<<10
)

var (
	// ErrInvalidKubernetesProfile reports a profile, or a rule's use of one,
	// that breaks the format.
	ErrInvalidKubernetesProfile = errors.New("policy publication: invalid Kubernetes access profile")
	// ErrKubernetesAccessLimit reports rules to one cluster whose grants or
	// scope table would pass what a gateway takes.
	ErrKubernetesAccessLimit = errors.New("policy publication: Kubernetes access over the cluster limits")
	// ErrKubernetesProfile reports profiles the database refuses (MTP08): a
	// content hash that names other content.
	ErrKubernetesProfile = errors.New("policy publication: Kubernetes access profile refused by the database")
	// ErrKubernetesProfileCluster reports a permission set the database
	// refuses for its cluster: one bound before to another cluster, or first
	// bound to a cluster that is not active in the Network (MTP10), or a
	// rule applying a set of another cluster (MTP09).
	ErrKubernetesProfileCluster = errors.New("policy publication: Kubernetes permission set of another cluster")
)

// KubernetesProfileID is a validated UUIDv7 naming one access profile of a
// Network: an edit keeps it, and rules follow the content it has in each
// release.
type KubernetesProfileID publicid.ID

// ParseKubernetesProfileID validates a canonical profile identity.
func ParseKubernetesProfileID(value string) (KubernetesProfileID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return KubernetesProfileID{}, ErrInvalidKubernetesProfile
	}
	return KubernetesProfileID(id), nil
}

// String returns the canonical lower-case UUID representation.
func (id KubernetesProfileID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the ID satisfies the UUIDv7 contract.
func (id KubernetesProfileID) IsValid() bool { return publicid.ID(id).IsValid() }

// KubernetesProfileParams describes one profile of a release.
type KubernetesProfileParams struct {
	ID KubernetesProfileID
	// Description is shown only: it is not part of what the release grants.
	Description string
	Profile     kubeprofile.Profile
	// Cluster is the cluster the set belongs to (K2h); zero for a set of
	// every cluster (legacy).
	Cluster kubecluster.ID
	// CopiedFrom names the set this one was copied from, shown only.
	CopiedFrom KubernetesProfileID
}

// KubernetesProfile is one profile as a release holds it: normalized, with
// the content hash rules pin.
type KubernetesProfile struct {
	id          KubernetesProfileID
	description string
	profile     kubeprofile.Profile
	contentHash [32]byte
	cluster     kubecluster.ID
	copiedFrom  KubernetesProfileID
}

// NewKubernetesProfile validates and normalizes a profile.
func NewKubernetesProfile(params KubernetesProfileParams) (KubernetesProfile, error) {
	hash, err := kubeprofile.ContentHash(params.Profile)
	if err != nil {
		return KubernetesProfile{}, errors.Join(ErrInvalidKubernetesProfile, err)
	}
	profile := KubernetesProfile{id: params.ID, description: params.Description,
		profile: kubeprofile.Normalize(params.Profile), contentHash: hash, cluster: params.Cluster,
		copiedFrom: params.CopiedFrom}
	if !profile.IsValid() {
		return KubernetesProfile{}, ErrInvalidKubernetesProfile
	}
	return profile, nil
}

// ID returns the profile identity.
func (profile KubernetesProfile) ID() KubernetesProfileID { return profile.id }

// Name returns the profile's name, part of its content.
func (profile KubernetesProfile) Name() string { return profile.profile.Name }

// Description returns the shown description.
func (profile KubernetesProfile) Description() string { return profile.description }

// Cluster returns the cluster the set belongs to; zero for a set of every
// cluster (legacy).
func (profile KubernetesProfile) Cluster() kubecluster.ID { return profile.cluster }

// CopiedFrom returns the set this one was copied from; zero when none.
func (profile KubernetesProfile) CopiedFrom() KubernetesProfileID { return profile.copiedFrom }

// WithCluster returns the set bound to cluster, for a compiler that keeps
// or resolves the set's binding.
func (profile KubernetesProfile) WithCluster(cluster kubecluster.ID) KubernetesProfile {
	profile.cluster = cluster
	return profile
}

// WithCopiedFrom returns the set with its copy origin.
func (profile KubernetesProfile) WithCopiedFrom(origin KubernetesProfileID) KubernetesProfile {
	profile.copiedFrom = origin
	return profile
}

// Profile returns a caller-owned copy of the normalized rules.
func (profile KubernetesProfile) Profile() kubeprofile.Profile { return cloneProfile(profile.profile) }

// cloneProfile copies a profile's lists; the profile is already normalized.
func cloneProfile(profile kubeprofile.Profile) kubeprofile.Profile {
	rules := func(rules []kubeprofile.Rule) []kubeprofile.Rule {
		if rules == nil {
			return nil
		}
		cloned := make([]kubeprofile.Rule, len(rules))
		for index, rule := range rules {
			cloned[index] = kubeprofile.Rule{APIGroups: slices.Clone(rule.APIGroups),
				Resources: slices.Clone(rule.Resources), Verbs: slices.Clone(rule.Verbs),
				ResourceNames: slices.Clone(rule.ResourceNames), NonResourceURLs: slices.Clone(rule.NonResourceURLs)}
		}
		return cloned
	}
	return kubeprofile.Profile{Name: profile.Name, Namespaced: rules(profile.Namespaced), Cluster: rules(profile.Cluster)}
}

// ContentHash returns the hash of the profile's content.
func (profile KubernetesProfile) ContentHash() [32]byte { return profile.contentHash }

// IsValid reports a valid identity, a bounded printable description and a
// content hash. Only NewKubernetesProfile sets the hash, from the checked
// content, and a profile never changes, so it is not hashed again here
// (review d2 L7).
func (profile KubernetesProfile) IsValid() bool {
	return profile.id.IsValid() && validProfileDescription(profile.description) &&
		profile.contentHash != [32]byte{} && profile.profile.Name != "" &&
		(profile.cluster == kubecluster.ID{} || profile.cluster.IsValid()) &&
		(profile.copiedFrom == KubernetesProfileID{} || profile.copiedFrom.IsValid())
}

// validProfileDescription reports valid UTF-8 of at most 512 characters
// without control characters but tab.
func validProfileDescription(description string) bool {
	if !utf8.ValidString(description) || utf8.RuneCountInString(description) > MaximumKubernetesProfileDescription {
		return false
	}
	for _, character := range description {
		if unicode.IsControl(character) && character != '\t' {
			return false
		}
	}
	return true
}

func compareKubernetesProfiles(first, second KubernetesProfile) int {
	firstID, secondID := publicid.ID(first.id).Bytes(), publicid.ID(second.id).Bytes()
	return bytes.Compare(firstID[:], secondID[:])
}

func cloneKubernetesProfiles(profiles []KubernetesProfile) []KubernetesProfile {
	cloned := make([]KubernetesProfile, len(profiles))
	for index, profile := range profiles {
		cloned[index] = profile
		cloned[index].profile = cloneProfile(profile.profile)
	}
	return cloned
}

// KubernetesAccessParams describes how a rule to a cluster applies a
// profile to its Kubernetes groups.
type KubernetesAccessParams struct {
	ProfileID KubernetesProfileID
	// ProfileHash is the content the profile has in the release.
	ProfileHash [32]byte
	// Namespaces are every namespace ("*" alone) or 1 to 64 DNS labels, in
	// any order.
	Namespaces  []string
	ClusterPart bool
	// Report lets requests through that the profile would refuse, and
	// reports them, until ReportUntil.
	Report      bool
	ReportUntil time.Time
}

// KubernetesAccess is a rule's use of a profile. The zero value is none: the
// rule grants its groups in full.
type KubernetesAccess struct {
	profileID   KubernetesProfileID
	profileHash [32]byte
	namespaces  []string
	clusterPart bool
	report      bool
	reportUntil time.Time
	scopeHash   [32]byte
}

// NewKubernetesAccess validates a rule's use of a profile and sorts its
// namespaces. A report deadline is kept to the millisecond, in UTC.
func NewKubernetesAccess(params KubernetesAccessParams) (KubernetesAccess, error) {
	scope, err := kubeprofile.ScopeHash(params.ProfileHash, params.Namespaces, params.ClusterPart)
	if err != nil {
		return KubernetesAccess{}, errors.Join(ErrInvalidKubernetesProfile, err)
	}
	namespaces := slices.Clone(params.Namespaces)
	slices.Sort(namespaces)
	access := KubernetesAccess{profileID: params.ProfileID, profileHash: params.ProfileHash,
		namespaces: slices.Compact(namespaces), clusterPart: params.ClusterPart, report: params.Report,
		scopeHash: scope}
	if params.Report {
		access.reportUntil = time.UnixMilli(params.ReportUntil.UnixMilli()).UTC()
	} else if !params.ReportUntil.IsZero() {
		return KubernetesAccess{}, ErrInvalidKubernetesProfile
	}
	if !access.IsValid() {
		return KubernetesAccess{}, ErrInvalidKubernetesProfile
	}
	return access, nil
}

// IsZero reports no profile: the rule grants its groups in full.
func (access KubernetesAccess) IsZero() bool {
	return !access.profileID.IsValid() && access.namespaces == nil
}

// ProfileID returns the profile the rule applies.
func (access KubernetesAccess) ProfileID() KubernetesProfileID { return access.profileID }

// ProfileHash returns the content of the profile the rule applies.
func (access KubernetesAccess) ProfileHash() [32]byte { return access.profileHash }

// Namespaces returns the rule's sorted namespaces.
func (access KubernetesAccess) Namespaces() []string { return slices.Clone(access.namespaces) }

// ClusterPart reports whether the rule turns the profile's cluster part on.
func (access KubernetesAccess) ClusterPart() bool { return access.clusterPart }

// Report reports whether the rule reports instead of enforces until
// ReportUntil.
func (access KubernetesAccess) Report() bool { return access.report }

// ReportUntil returns when a reporting rule starts to enforce.
func (access KubernetesAccess) ReportUntil() time.Time { return access.reportUntil }

// ScopeHash returns the hash gateways name the scope by (mtcp-v1 §7.12).
func (access KubernetesAccess) ScopeHash() [32]byte { return access.scopeHash }

// IsValid reports the zero access, or a profile identity and content with
// sorted distinct namespaces, the scope hash they make, and a report
// deadline exactly when the rule reports.
func (access KubernetesAccess) IsValid() bool {
	if access.IsZero() {
		return access.profileHash == [32]byte{} && !access.clusterPart && !access.report &&
			access.reportUntil.IsZero() && access.scopeHash == [32]byte{}
	}
	if !access.profileID.IsValid() || access.profileHash == [32]byte{} ||
		access.report == access.reportUntil.IsZero() ||
		!access.reportUntil.Equal(time.UnixMilli(access.reportUntil.UnixMilli())) {
		return false
	}
	for index := 1; index < len(access.namespaces); index++ {
		if access.namespaces[index-1] >= access.namespaces[index] {
			return false
		}
	}
	scope, err := kubeprofile.ScopeHash(access.profileHash, access.namespaces, access.clusterPart)
	return err == nil && scope == access.scopeHash
}

// equal reports the same use of the same profile content, or no profile in
// both.
func (access KubernetesAccess) equal(other KubernetesAccess) bool {
	return access.profileID == other.profileID && access.scopeHash == other.scopeHash &&
		access.report == other.report && access.reportUntil.Equal(other.reportUntil)
}

func (access KubernetesAccess) clone() KubernetesAccess {
	access.namespaces = slices.Clone(access.namespaces)
	return access
}
