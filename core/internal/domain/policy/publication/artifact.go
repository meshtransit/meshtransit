package publication

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubeprofile"
)

const (
	policyHashDomainV1 = "meshtransit/policy-release/v1\x00"
	policyHashDomainV2 = "meshtransit/policy-release/v2\x00"
	policyHashDomainV3 = "meshtransit/policy-release/v3\x00"
	policyHashDomainV4 = "meshtransit/policy-release/v4\x00"
	policyHashDomainV5 = "meshtransit/policy-release/v5\x00"
	policyHashDomainV6 = "meshtransit/policy-release/v6\x00"
	policyHashDomainV7 = "meshtransit/policy-release/v7\x00"
	// policyHashDomainV8 adds the Kubernetes groups of rules to a cluster
	// (K1a3); a release whose rules name none keeps an earlier domain.
	policyHashDomainV8 = "meshtransit/policy-release/v8\x00"
	// policyHashDomainV9 adds the access profiles of rules to clusters and
	// the profiles of the release (K2); a release whose rules apply none
	// keeps an earlier domain.
	policyHashDomainV9               = "meshtransit/policy-release/v9\x00"
	resourceCompilerFormatV2         = 2
	resourceGroupCompilerFormatV3    = 3
	importedResourceCompilerFormatV4 = 4
	// MaximumCompilerFormatVersion bounds the version encoded in durable releases.
	MaximumCompilerFormatVersion = 65535
)

// ErrInvalidCandidate reports an unsafe or internally inconsistent compiled candidate.
var ErrInvalidCandidate = errors.New("policy publication: invalid candidate")

// SemanticHash is the canonical SHA-256 digest of compiled packet semantics.
type SemanticHash [sha256.Size]byte

// NewSemanticHash validates a non-zero canonical digest loaded at a boundary.
func NewSemanticHash(value [sha256.Size]byte) (SemanticHash, error) {
	hash := SemanticHash(value)
	if !hash.IsValid() {
		return SemanticHash{}, ErrInvalidCandidate
	}
	return hash, nil
}

// Bytes returns a copy of the digest.
func (hash SemanticHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether the digest is non-zero.
func (hash SemanticHash) IsValid() bool { return hash != SemanticHash{} }

// Candidate is a complete immutable compiled policy ready for short activation.
// Its semantic hash excludes the allocated revision so identical semantics hash
// identically across rollback or re-publication.
type Candidate struct {
	snapshot                     policy.Snapshot
	compilerFormatVersion        int
	semanticHash                 SemanticHash
	resourceDestinations         []ResourceDestination
	resourceGroupDestinations    []ResourceGroupDestination
	importedResourceDestinations []ImportedResourceDestination
	kubernetesProfiles           []KubernetesProfile
	// knowsKubernetesProfiles: the compiler read the replaced release's
	// profiles and rule access, so the candidate names every profile a rule
	// keeps. Not part of what the release grants.
	knowsKubernetesProfiles bool
	groupRules              []GroupRule
	routeRules              []RouteRule
	exitRules               []ExitRule
}

// hashLevel is what a release hash covers of Kubernetes access: the domain
// a Core of each era computes.
type hashLevel byte

const (
	// hashBeforeGroups: no Kubernetes groups (before K1a3).
	hashBeforeGroups hashLevel = iota
	// hashGroups: groups, not profiles (domain v8, K1a3 to K2c).
	hashGroups
	// hashProfiles: groups and profiles (domain v9, K2).
	hashProfiles
)

// NewCandidate validates and hashes one compiled policy artifact.
func NewCandidate(snapshot policy.Snapshot, compilerFormatVersion int) (Candidate, error) {
	return newCandidate(snapshot, compilerFormatVersion, nil)
}

// NewCandidateWithResourceDestinations constructs a format-v2 candidate whose
// compiled Device edges retain exact Resource resolution provenance.
func NewCandidateWithResourceDestinations(
	snapshot policy.Snapshot,
	destinations []ResourceDestination,
) (Candidate, error) {
	if len(destinations) == 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	return newCandidate(snapshot, resourceCompilerFormatV2, destinations)
}

// NewCandidateWithResourceGroupDestinations constructs a format-v3 candidate
// whose expanded Device edges retain exact Resource Group and member provenance.
func NewCandidateWithResourceGroupDestinations(
	snapshot policy.Snapshot,
	resourceDestinations []ResourceDestination,
	groupDestinations []ResourceGroupDestination,
) (Candidate, error) {
	if len(groupDestinations) == 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	return newCandidateWithDestinations(
		snapshot,
		resourceGroupCompilerFormatV3,
		resourceDestinations,
		groupDestinations,
	)
}

// NewCandidateWithImportedResourceDestinations constructs a format-v4
// candidate retaining bilateral Imported Resource intent without manufacturing
// a same-Network packet edge.
func NewCandidateWithImportedResourceDestinations(
	snapshot policy.Snapshot,
	resourceDestinations []ResourceDestination,
	groupDestinations []ResourceGroupDestination,
	importedDestinations []ImportedResourceDestination,
) (Candidate, error) {
	if len(importedDestinations) == 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	return newCandidateWithAllDestinations(
		snapshot,
		importedResourceCompilerFormatV4,
		resourceDestinations,
		groupDestinations,
		importedDestinations,
	)
}

func newCandidate(
	snapshot policy.Snapshot,
	compilerFormatVersion int,
	destinations []ResourceDestination,
) (Candidate, error) {
	return newCandidateWithAllDestinations(
		snapshot, compilerFormatVersion, destinations, nil, nil,
	)
}

func newCandidateWithDestinations(
	snapshot policy.Snapshot,
	compilerFormatVersion int,
	destinations []ResourceDestination,
	groupDestinations []ResourceGroupDestination,
) (Candidate, error) {
	return newCandidateWithAllDestinations(
		snapshot, compilerFormatVersion, destinations, groupDestinations, nil,
	)
}

func newCandidateWithAllDestinations(
	snapshot policy.Snapshot,
	compilerFormatVersion int,
	destinations []ResourceDestination,
	groupDestinations []ResourceGroupDestination,
	importedDestinations []ImportedResourceDestination,
) (Candidate, error) {
	if !snapshot.IsValid() || compilerFormatVersion <= 0 ||
		compilerFormatVersion > MaximumCompilerFormatVersion {
		return Candidate{}, ErrInvalidCandidate
	}
	destinations = cloneResourceDestinations(destinations)
	slices.SortFunc(destinations, compareResourceDestinations)
	groupDestinations = cloneResourceGroupDestinations(groupDestinations)
	slices.SortFunc(groupDestinations, compareResourceGroupDestinations)
	importedDestinations = cloneImportedResourceDestinations(importedDestinations)
	slices.SortFunc(importedDestinations, compareImportedResourceDestinations)
	candidate := Candidate{
		snapshot:                     snapshot,
		compilerFormatVersion:        compilerFormatVersion,
		resourceDestinations:         destinations,
		resourceGroupDestinations:    groupDestinations,
		importedResourceDestinations: importedDestinations,
	}
	candidate.semanticHash = hashCandidate(candidate)
	if !candidate.IsValid() {
		return Candidate{}, ErrInvalidCandidate
	}
	return candidate, nil
}

// Snapshot returns the immutable Node-resolved packet policy.
func (candidate Candidate) Snapshot() policy.Snapshot { return candidate.snapshot }

// CompilerFormatVersion returns the bounded compiler representation version.
func (candidate Candidate) CompilerFormatVersion() int { return candidate.compilerFormatVersion }

// SemanticHash returns the canonical compiled semantics digest.
func (candidate Candidate) SemanticHash() SemanticHash { return candidate.semanticHash }

// ResourceDestinations returns caller-owned Resource resolution provenance.
func (candidate Candidate) ResourceDestinations() []ResourceDestination {
	return cloneResourceDestinations(candidate.resourceDestinations)
}

// ResourceGroupDestinations returns caller-owned group expansion provenance.
func (candidate Candidate) ResourceGroupDestinations() []ResourceGroupDestination {
	return cloneResourceGroupDestinations(candidate.resourceGroupDestinations)
}

// ImportedResourceDestinations returns caller-owned bilateral selector provenance.
func (candidate Candidate) ImportedResourceDestinations() []ImportedResourceDestination {
	return cloneImportedResourceDestinations(candidate.importedResourceDestinations)
}

// WithKubernetesProfiles returns the candidate with the access profiles of
// its release, attached before any group rule that applies one. IDs and names
// are unique and there are at most MaximumKubernetesProfiles.
func (candidate Candidate) WithKubernetesProfiles(profiles []KubernetesProfile) (Candidate, error) {
	if !candidate.IsValid() || len(candidate.kubernetesProfiles) > 0 || len(candidate.groupRules) > 0 ||
		len(candidate.routeRules) > 0 || len(candidate.exitRules) > 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	extended := candidate
	extended.kubernetesProfiles = cloneKubernetesProfiles(profiles)
	slices.SortFunc(extended.kubernetesProfiles, compareKubernetesProfiles)
	extended.semanticHash = hashCandidate(extended)
	if !extended.IsValid() {
		return Candidate{}, ErrInvalidCandidate
	}
	return extended, nil
}

// WithKubernetesProfilesKnown marks a candidate compiled knowing the
// profiles and rule access of the release it replaces: only such a
// candidate may be written by a writer that hashes profiles, which no
// longer carries a rule's profile it is not sent.
func (candidate Candidate) WithKubernetesProfilesKnown() Candidate {
	candidate.knowsKubernetesProfiles = true
	return candidate
}

// KnowsKubernetesProfiles reports a candidate compiled knowing the profiles
// of the release it replaces.
func (candidate Candidate) KnowsKubernetesProfiles() bool { return candidate.knowsKubernetesProfiles }

// KubernetesAccessChanged reports whether proposed changes what baseline
// holds of Kubernetes access in a way an approver must see: any profile of
// the release (ID, content, description), or a rule kept in both whose
// profile use changes, or a rule that newly applies a profile. A rule
// removed, or a rule without a profile in both, changes nothing here.
func KubernetesAccessChanged(baseline, proposed Candidate) bool {
	if len(baseline.kubernetesProfiles) != len(proposed.kubernetesProfiles) {
		return true
	}
	for index, profile := range baseline.kubernetesProfiles {
		other := proposed.kubernetesProfiles[index]
		if profile.id != other.id || profile.contentHash != other.contentHash ||
			profile.description != other.description {
			return true
		}
	}
	held := make(map[policy.RuleID]KubernetesAccess, len(baseline.groupRules))
	for _, rule := range baseline.groupRules {
		held[rule.ruleID] = rule.kubernetesAccess
	}
	for _, rule := range proposed.groupRules {
		before, kept := held[rule.ruleID]
		if (kept || !rule.kubernetesAccess.IsZero()) && !before.equal(rule.kubernetesAccess) {
			return true
		}
	}
	return false
}

// KubernetesProfiles returns caller-owned access profiles of the release,
// sorted by ID.
func (candidate Candidate) KubernetesProfiles() []KubernetesProfile {
	return cloneKubernetesProfiles(candidate.kubernetesProfiles)
}

// WithGroupRules returns the candidate with Access Rules that select Device
// Groups. Each rule ID is unique and used by no other rule of the candidate,
// and the candidate stays within MaximumRules facts.
func (candidate Candidate) WithGroupRules(rules []GroupRule) (Candidate, error) {
	// Group rules attach before route and exit rules, whose identities they
	// would otherwise not be checked against.
	if !candidate.IsValid() || len(candidate.groupRules) > 0 || len(candidate.routeRules) > 0 ||
		len(candidate.exitRules) > 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	if err := CheckKubernetesAccessLimits(rules, candidate.kubernetesProfiles); err != nil {
		return Candidate{}, err
	}
	extended := candidate
	extended.groupRules = cloneGroupRules(rules)
	slices.SortFunc(extended.groupRules, compareGroupRules)
	extended.semanticHash = hashCandidate(extended)
	if !extended.IsValid() {
		return Candidate{}, ErrInvalidCandidate
	}
	return extended, nil
}

// WithRouteRules returns the candidate with Access Rules whose destination is
// a Site. Each rule ID is unique and used by no other rule of the candidate,
// rules of different Sites never overlap, and the candidate stays within
// MaximumRules facts.
func (candidate Candidate) WithRouteRules(rules []RouteRule) (Candidate, error) {
	if !candidate.IsValid() || len(candidate.routeRules) > 0 || len(candidate.exitRules) > 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	if err := CheckRouteOverlap(rules); err != nil {
		return Candidate{}, err
	}
	extended := candidate
	extended.routeRules = cloneRouteRules(rules)
	slices.SortFunc(extended.routeRules, compareRouteRules)
	extended.semanticHash = hashCandidate(extended)
	if !extended.IsValid() {
		return Candidate{}, ErrInvalidCandidate
	}
	return extended, nil
}

// RouteRules returns caller-owned rules whose destination is a Site.
func (candidate Candidate) RouteRules() []RouteRule { return cloneRouteRules(candidate.routeRules) }

// WithExitRules returns the candidate with Access Rules whose destination is
// an Exit Pool, attached after any route rules. Each rule ID is unique and
// used by no other rule of the candidate, and the candidate stays within
// MaximumRules facts.
func (candidate Candidate) WithExitRules(rules []ExitRule) (Candidate, error) {
	if !candidate.IsValid() || len(candidate.exitRules) > 0 {
		return Candidate{}, ErrInvalidCandidate
	}
	extended := candidate
	extended.exitRules = cloneExitRules(rules)
	slices.SortFunc(extended.exitRules, compareExitRules)
	extended.semanticHash = hashCandidate(extended)
	if !extended.IsValid() {
		return Candidate{}, ErrInvalidCandidate
	}
	return extended, nil
}

// ExitRules returns caller-owned rules whose destination is an Exit Pool.
func (candidate Candidate) ExitRules() []ExitRule { return cloneExitRules(candidate.exitRules) }

// ProjectionCount is how many stored rule facts the release holds: compiled
// Device pairs, Imported Resource selectors, group rules, route rules and
// exit rules, in that order.
func (candidate Candidate) ProjectionCount() int {
	return len(candidate.snapshot.Rules()) + len(candidate.importedResourceDestinations) + len(candidate.groupRules) +
		len(candidate.routeRules) + len(candidate.exitRules)
}

// GroupRules returns caller-owned rules that select Device Groups.
func (candidate Candidate) GroupRules() []GroupRule { return cloneGroupRules(candidate.groupRules) }

// IsValid reports whether all candidate fields and their digest agree.
func (candidate Candidate) IsValid() bool {
	return candidate.snapshot.IsValid() && candidate.compilerFormatVersion > 0 &&
		candidate.compilerFormatVersion <= MaximumCompilerFormatVersion &&
		validResourceDestinations(candidate) &&
		validResourceGroupDestinations(candidate) &&
		validImportedResourceDestinations(candidate) &&
		validKubernetesProfiles(candidate.kubernetesProfiles) &&
		validGroupRules(candidate) &&
		validRouteRules(candidate) &&
		validExitRules(candidate) &&
		candidate.semanticHash.IsValid() &&
		candidate.semanticHash == hashCandidate(candidate)
}

func validGroupRules(candidate Candidate) bool {
	if len(candidate.groupRules) == 0 {
		return true
	}
	snapshotRules := candidate.snapshot.Rules()
	if len(snapshotRules)+len(candidate.importedResourceDestinations)+len(candidate.groupRules) > policy.MaximumRules {
		return false
	}
	taken := make(map[policy.RuleID]struct{}, len(snapshotRules)+len(candidate.importedResourceDestinations))
	for _, rule := range snapshotRules {
		taken[rule.ID()] = struct{}{}
	}
	for _, destination := range candidate.importedResourceDestinations {
		taken[destination.ruleID] = struct{}{}
	}
	for index, rule := range candidate.groupRules {
		if !rule.IsValid() || (index > 0 && compareGroupRules(candidate.groupRules[index-1], rule) >= 0) {
			return false
		}
		if _, used := taken[rule.ruleID]; used {
			return false
		}
	}
	// A rule applies a profile of the release, with the content it has there.
	profiles := make(map[KubernetesProfileID][32]byte, len(candidate.kubernetesProfiles))
	for _, profile := range candidate.kubernetesProfiles {
		profiles[profile.id] = profile.contentHash
	}
	for _, rule := range candidate.groupRules {
		if access := rule.kubernetesAccess; !access.IsZero() {
			if hash, found := profiles[access.profileID]; !found || hash != access.profileHash {
				return false
			}
		}
	}
	return CheckKubernetesAccessLimits(candidate.groupRules, candidate.kubernetesProfiles) == nil
}

// validKubernetesProfiles reports at most MaximumKubernetesProfiles valid
// profiles, strictly sorted by ID, with distinct names.
func validKubernetesProfiles(profiles []KubernetesProfile) bool {
	if len(profiles) > MaximumKubernetesProfiles {
		return false
	}
	names := make(map[string]struct{}, len(profiles))
	for index, profile := range profiles {
		if !profile.IsValid() || index > 0 && compareKubernetesProfiles(profiles[index-1], profile) >= 0 {
			return false
		}
		if _, duplicate := names[profile.Name()]; duplicate {
			return false
		}
		names[profile.Name()] = struct{}{}
	}
	return true
}

// clusterKubernetesAccess is what the rules to one cluster grant, as the
// gateway's map will carry it.
type clusterKubernetesAccess struct {
	groups     map[string]struct{}
	grantKeys  map[kubernetesGrantKey]struct{}
	profiles   map[[32]byte]struct{}
	scopes     map[[32]byte]struct{}
	tableBytes int
}

// kubernetesGrantKey is what grants of one peer merge by (mtcp-v1 §7.12):
// the group, then for a profile the scope, mode and report deadline.
type kubernetesGrantKey struct {
	group       string
	scope       [32]byte
	report      bool
	reportUntil int64
}

// CheckKubernetesAccessLimits reports ErrKubernetesAccessLimit when the
// rules to one cluster name more than 64 Kubernetes groups, make more than
// 64 distinct grant keys, or a scope table over its profile, scope or byte
// bounds: a gateway would refuse what the release grants. A profile the
// rules apply is one of profiles; one that is not counts as the largest.
func CheckKubernetesAccessLimits(rules []GroupRule, profiles []KubernetesProfile) error {
	sizes := make(map[[32]byte]int, len(profiles))
	for _, profile := range profiles {
		sizes[profile.contentHash] = encodedProfileBound(profile.profile)
	}
	clusters := make(map[kubecluster.ID]*clusterKubernetesAccess)
	for _, rule := range rules {
		if rule.kubernetesGroups == nil {
			continue
		}
		cluster := clusters[rule.cluster]
		if cluster == nil {
			cluster = &clusterKubernetesAccess{groups: map[string]struct{}{},
				grantKeys: map[kubernetesGrantKey]struct{}{}, profiles: map[[32]byte]struct{}{},
				scopes: map[[32]byte]struct{}{}}
			clusters[rule.cluster] = cluster
		}
		access := rule.kubernetesAccess
		for _, group := range rule.kubernetesGroups {
			cluster.groups[group] = struct{}{}
			key := kubernetesGrantKey{group: group}
			if !access.IsZero() {
				key.scope, key.report = access.scopeHash, access.report
				if access.report {
					key.reportUntil = access.reportUntil.UnixMilli()
				}
			}
			cluster.grantKeys[key] = struct{}{}
		}
		if !access.IsZero() {
			cluster.addScope(access, sizes)
		}
		if len(cluster.groups) > kubecluster.MaximumClusterKubernetesGroups ||
			len(cluster.grantKeys) > MaximumClusterKubernetesGrantKeys ||
			len(cluster.profiles) > MaximumClusterKubernetesProfiles ||
			len(cluster.scopes) > MaximumClusterKubernetesScopes || cluster.tableBytes > MaximumClusterScopeTableBytes {
			return ErrKubernetesAccessLimit
		}
	}
	return nil
}

// addScope counts the rule's scope and profile into the cluster's table
// once each, by bounds of their encoded sizes.
func (cluster *clusterKubernetesAccess) addScope(access KubernetesAccess, sizes map[[32]byte]int) {
	if _, seen := cluster.scopes[access.scopeHash]; !seen {
		cluster.scopes[access.scopeHash] = struct{}{}
		cluster.tableBytes += encodedScopeBound(access.namespaces)
	}
	if _, seen := cluster.profiles[access.profileHash]; !seen {
		cluster.profiles[access.profileHash] = struct{}{}
		size, known := sizes[access.profileHash]
		if !known {
			size = MaximumClusterScopeTableBytes + 1
		}
		cluster.tableBytes += size
	}
}

// encodedProfileBound bounds the bytes a profile takes in a scope table
// (mtcp-v1 §7.12): its entry, hash, profile ID and name fields, and for each
// rule its field and each string's tag, length and bytes, all fields
// numbered below 16 and every length below 2^21.
func encodedProfileBound(profile kubeprofile.Profile) int {
	size := 4 + 34 + 40 + 4 + len(profile.Name)
	for _, rule := range slices.Concat(profile.Namespaced, profile.Cluster) {
		size += 4
		for _, value := range slices.Concat(rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames,
			rule.NonResourceURLs) {
			size += 4 + len(value)
		}
	}
	return size
}

// encodedScopeBound bounds the bytes a scope takes in a scope table: its
// entry, its two hashes, cluster part and namespaces.
func encodedScopeBound(namespaces []string) int {
	size := 4 + 34 + 34 + 2
	for _, namespace := range namespaces {
		size += 2 + len(namespace)
	}
	return size
}

func validRouteRules(candidate Candidate) bool {
	if len(candidate.routeRules) == 0 {
		return true
	}
	granted := 0
	for _, rule := range candidate.routeRules {
		granted += len(rule.prefixes)
	}
	if candidate.ProjectionCount() > policy.MaximumRules || granted > MaximumGrantedRoutePrefixes ||
		CheckRouteOverlap(candidate.routeRules) != nil {
		return false
	}
	snapshotRules := candidate.snapshot.Rules()
	taken := make(map[policy.RuleID]struct{}, candidate.ProjectionCount())
	for _, rule := range snapshotRules {
		taken[rule.ID()] = struct{}{}
	}
	for _, destination := range candidate.importedResourceDestinations {
		taken[destination.ruleID] = struct{}{}
	}
	for _, rule := range candidate.groupRules {
		taken[rule.ruleID] = struct{}{}
	}
	for index, rule := range candidate.routeRules {
		if !rule.IsValid() || (index > 0 && compareRouteRules(candidate.routeRules[index-1], rule) >= 0) {
			return false
		}
		if _, used := taken[rule.ruleID]; used {
			return false
		}
	}
	return true
}

func validExitRules(candidate Candidate) bool {
	if len(candidate.exitRules) == 0 {
		return true
	}
	if candidate.ProjectionCount() > policy.MaximumRules {
		return false
	}
	taken := make(map[policy.RuleID]struct{}, candidate.ProjectionCount())
	for _, rule := range candidate.snapshot.Rules() {
		taken[rule.ID()] = struct{}{}
	}
	for _, destination := range candidate.importedResourceDestinations {
		taken[destination.ruleID] = struct{}{}
	}
	for _, rule := range candidate.groupRules {
		taken[rule.ruleID] = struct{}{}
	}
	for _, rule := range candidate.routeRules {
		taken[rule.ruleID] = struct{}{}
	}
	for index, rule := range candidate.exitRules {
		if !rule.IsValid() || (index > 0 && compareExitRules(candidate.exitRules[index-1], rule) >= 0) {
			return false
		}
		if _, used := taken[rule.ruleID]; used {
			return false
		}
	}
	return true
}

func validImportedResourceDestinations(candidate Candidate) bool {
	destinations := candidate.importedResourceDestinations
	if len(destinations) == 0 {
		return true
	}
	if candidate.compilerFormatVersion != importedResourceCompilerFormatV4 ||
		len(destinations) > policy.MaximumRules {
		return false
	}
	usedRuleIDs := make(map[policy.RuleID]struct{},
		len(candidate.resourceDestinations)+len(candidate.resourceGroupDestinations)+
			len(candidate.snapshot.Rules()),
	)
	for _, rule := range candidate.snapshot.Rules() {
		usedRuleIDs[rule.ID()] = struct{}{}
	}
	for _, destination := range candidate.resourceDestinations {
		usedRuleIDs[destination.ruleID] = struct{}{}
	}
	for _, destination := range candidate.resourceGroupDestinations {
		usedRuleIDs[destination.ruleID] = struct{}{}
	}
	for index, destination := range destinations {
		if !destination.IsValid() ||
			destination.resolution.ConsumerScope() != candidate.snapshot.Scope() ||
			(index > 0 && compareImportedResourceDestinations(destinations[index-1], destination) >= 0) {
			return false
		}
		if _, duplicate := usedRuleIDs[destination.ruleID]; duplicate {
			return false
		}
		usedRuleIDs[destination.ruleID] = struct{}{}
	}
	return true
}

func validResourceDestinations(candidate Candidate) bool {
	destinations := candidate.resourceDestinations
	if len(destinations) == 0 {
		return true
	}
	if (candidate.compilerFormatVersion != resourceCompilerFormatV2 &&
		candidate.compilerFormatVersion != resourceGroupCompilerFormatV3 &&
		candidate.compilerFormatVersion != importedResourceCompilerFormatV4) ||
		len(destinations) > len(candidate.snapshot.Rules()) {
		return false
	}
	rules := candidate.snapshot.Rules()
	for index, destination := range destinations {
		if !destination.IsValid() || destination.reference.Scope() != candidate.snapshot.Scope() ||
			(index > 0 && (destinations[index-1].ruleID == destination.ruleID ||
				compareResourceDestinations(destinations[index-1], destination) >= 0)) {
			return false
		}
		matches := 0
		for _, rule := range rules {
			if rule.ID() == destination.ruleID &&
				rule.DestinationNodeID() == destination.destinationNodeID {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func validResourceGroupDestinations(candidate Candidate) bool {
	destinations := candidate.resourceGroupDestinations
	if len(destinations) == 0 {
		return true
	}
	if (candidate.compilerFormatVersion != resourceGroupCompilerFormatV3 &&
		candidate.compilerFormatVersion != importedResourceCompilerFormatV4) ||
		len(destinations) > len(candidate.snapshot.Rules()) {
		return false
	}
	directRules := make(map[policy.RuleID]struct{}, len(candidate.resourceDestinations))
	for _, destination := range candidate.resourceDestinations {
		directRules[destination.ruleID] = struct{}{}
	}
	rules := candidate.snapshot.Rules()
	for index, destination := range destinations {
		if !destination.IsValid() || destination.scope != candidate.snapshot.Scope() ||
			(index > 0 && (destinations[index-1].ruleID == destination.ruleID ||
				compareResourceGroupDestinations(destinations[index-1], destination) >= 0)) {
			return false
		}
		if _, collision := directRules[destination.ruleID]; collision {
			return false
		}
		groupRules := 0
		var template policy.Rule
		for _, rule := range rules {
			if rule.ID() == destination.ruleID {
				if groupRules == 0 {
					template = rule
				} else if rule.SourceNodeID() != template.SourceNodeID() ||
					rule.Protocol() != template.Protocol() ||
					!slices.Equal(rule.DestinationPortRanges(), template.DestinationPortRanges()) {
					return false
				}
				groupRules++
			}
		}
		if groupRules != len(destination.members) {
			return false
		}
		for _, member := range destination.members {
			memberMatches := 0
			for _, rule := range rules {
				if rule.ID() == destination.ruleID {
					if rule.DestinationNodeID() == member.destinationNodeID {
						memberMatches++
					}
				}
			}
			if memberMatches != 1 {
				return false
			}
		}
	}
	return true
}

// hashCandidate hashes what the candidate grants, the Kubernetes groups and
// access profiles of its rules to clusters included.
func hashCandidate(candidate Candidate) SemanticHash {
	return hashCandidateWith(candidate, candidate.hashLevel())
}

// hashLevel is what the candidate's own hash covers: profiles when a rule
// applies one, else groups when a rule names some.
func (candidate Candidate) hashLevel() hashLevel {
	switch {
	case candidate.CoversKubernetesProfiles():
		return hashProfiles
	case candidate.CoversKubernetesGroups():
		return hashGroups
	default:
		return hashBeforeGroups
	}
}

// hashCandidateWith hashes the candidate as a Core of the level's era
// would: in domain v9 with groups and profiles, v8 with groups only, or
// before K1a3 without either.
func hashCandidateWith(candidate Candidate, level hashLevel) SemanticHash {
	rules := candidate.snapshot.Rules()
	domain := policyHashDomainV1
	if level == hashProfiles {
		domain = policyHashDomainV9
	} else if level == hashGroups {
		domain = policyHashDomainV8
	} else if len(candidate.exitRules) > 0 {
		domain = policyHashDomainV7
	} else if len(candidate.routeRules) > 0 {
		domain = policyHashDomainV6
	} else if len(candidate.groupRules) > 0 {
		domain = policyHashDomainV5
	} else if len(candidate.importedResourceDestinations) > 0 {
		domain = policyHashDomainV4
	} else if len(candidate.resourceGroupDestinations) > 0 {
		domain = policyHashDomainV3
	} else if len(candidate.resourceDestinations) > 0 {
		domain = policyHashDomainV2
	}
	encoded := make(
		[]byte,
		0,
		len(domain)+48+len(rules)*80+len(candidate.resourceDestinations)*128+
			len(candidate.resourceGroupDestinations)*192+
			len(candidate.importedResourceDestinations)*320,
	)
	encoded = append(encoded, domain...)
	workspaceID := candidate.snapshot.Scope().WorkspaceID().Bytes()
	networkID := candidate.snapshot.Scope().NetworkID().Bytes()
	encoded = append(encoded, workspaceID[:]...)
	encoded = append(encoded, networkID[:]...)
	encoded = appendInt64(encoded, int64(candidate.compilerFormatVersion))
	encoded = appendUint64(encoded, uint64(len(rules)))
	for _, rule := range rules {
		ruleID := publicid.ID(rule.ID()).Bytes()
		sourceID := publicid.ID(rule.SourceNodeID()).Bytes()
		destinationID := publicid.ID(rule.DestinationNodeID()).Bytes()
		encoded = append(encoded, ruleID[:]...)
		encoded = append(encoded, sourceID[:]...)
		encoded = append(encoded, destinationID[:]...)
		encoded = append(encoded, byte(rule.Protocol()))
		portRanges := rule.DestinationPortRanges()
		encoded = appendUint64(encoded, uint64(len(portRanges)))
		for _, portRange := range portRanges {
			encoded = appendUint16(encoded, portRange.First())
			encoded = appendUint16(encoded, portRange.Last())
		}
	}
	switch domain {
	case policyHashDomainV6:
		encoded = append(encoded, presentSections(candidate))
	case policyHashDomainV7:
		// v7 also tags route rules: an exit rule may come without them.
		present := presentSections(candidate)
		if len(candidate.routeRules) > 0 {
			present |= 1 << 4
		}
		encoded = append(encoded, present)
	case policyHashDomainV8, policyHashDomainV9:
		// v8 tags route and exit rules: either may come without the other.
		present := presentSections(candidate)
		if len(candidate.routeRules) > 0 {
			present |= 1 << 4
		}
		if len(candidate.exitRules) > 0 {
			present |= 1 << 5
		}
		encoded = append(encoded, present)
	}
	if len(candidate.resourceDestinations) > 0 || len(candidate.resourceGroupDestinations) > 0 {
		encoded = appendUint64(encoded, uint64(len(candidate.resourceDestinations)))
		for _, destination := range candidate.resourceDestinations {
			ruleID := publicid.ID(destination.ruleID).Bytes()
			resourceID := destination.reference.ResourceID().Bytes()
			destinationID := publicid.ID(destination.destinationNodeID).Bytes()
			resourceHash := destination.resourceSemanticHash.Bytes()
			encoded = append(encoded, ruleID[:]...)
			encoded = append(encoded, resourceID[:]...)
			encoded = appendInt64(encoded, destination.reference.ResourceVersion())
			encoded = appendInt64(encoded, destination.reference.TargetGeneration())
			encoded = appendInt64(encoded, destination.inventoryRevision)
			encoded = append(encoded, destinationID[:]...)
			encoded = append(encoded, resourceHash[:]...)
		}
	}
	if len(candidate.resourceGroupDestinations) > 0 {
		encoded = appendUint64(encoded, uint64(len(candidate.resourceGroupDestinations)))
		for _, destination := range candidate.resourceGroupDestinations {
			ruleID := publicid.ID(destination.ruleID).Bytes()
			groupID := destination.resourceGroupID.Bytes()
			groupHash := destination.groupSemanticHash.Bytes()
			encoded = append(encoded, ruleID[:]...)
			encoded = append(encoded, groupID[:]...)
			encoded = appendInt64(encoded, destination.groupVersion)
			encoded = appendInt64(encoded, destination.definitionVersion)
			encoded = appendInt64(encoded, destination.groupRevision)
			encoded = append(encoded, groupHash[:]...)
			encoded = appendUint64(encoded, uint64(len(destination.members)))
			for _, member := range destination.members {
				resourceID := member.reference.ResourceID().Bytes()
				destinationID := publicid.ID(member.destinationNodeID).Bytes()
				resourceHash := member.resourceSemanticHash.Bytes()
				encoded = append(encoded, resourceID[:]...)
				encoded = appendInt64(encoded, member.reference.ResourceVersion())
				encoded = appendInt64(encoded, member.reference.TargetGeneration())
				encoded = appendInt64(encoded, member.inventoryRevision)
				encoded = append(encoded, destinationID[:]...)
				encoded = append(encoded, resourceHash[:]...)
			}
		}
	}
	if len(candidate.importedResourceDestinations) > 0 {
		encoded = appendUint64(encoded, uint64(len(candidate.importedResourceDestinations)))
		for _, destination := range candidate.importedResourceDestinations {
			resolution := destination.resolution
			contract := resolution.Contract()
			binding := contract.Resource()
			ruleID := publicid.ID(destination.ruleID).Bytes()
			sourceID := publicid.ID(destination.sourceNodeID).Bytes()
			importedID := resolution.ImportedResourceID().Bytes()
			contractID := contract.ID().Bytes()
			exportID := contract.ExportID().Bytes()
			providerWorkspaceID := contract.ProviderScope().WorkspaceID().Bytes()
			providerNetworkID := contract.ProviderScope().NetworkID().Bytes()
			resourceID := binding.ResourceID().Bytes()
			resourceHash := binding.SemanticHash().Bytes()
			trafficHash := contract.MaximumTraffic().Hash()
			encoded = append(encoded, ruleID[:]...)
			encoded = append(encoded, sourceID[:]...)
			encoded = append(encoded, importedID[:]...)
			encoded = appendInt64(encoded, resolution.ImportedResourceVersion())
			encoded = append(encoded, contractID[:]...)
			encoded = appendInt64(encoded, contract.Version())
			encoded = append(encoded, exportID[:]...)
			encoded = appendInt64(encoded, resolution.ExportVersion())
			encoded = append(encoded, providerWorkspaceID[:]...)
			encoded = append(encoded, providerNetworkID[:]...)
			encoded = append(encoded, resourceID[:]...)
			encoded = appendInt64(encoded, binding.ResourceVersion())
			encoded = appendInt64(encoded, binding.TargetGeneration())
			encoded = append(encoded, resourceHash[:]...)
			encoded = appendInt64(encoded, resolution.ProviderInventoryRevision())
			encoded = appendInt64(encoded, resolution.ProviderSharingRevision())
			encoded = appendInt64(encoded, resolution.ConsumerSharingRevision())
			encoded = appendInt64(encoded, contract.ProviderAuthorityGeneration())
			encoded = appendInt64(encoded, contract.ConsumerAuthorityGeneration())
			encoded = appendInt64(encoded, contract.RecoveryEpoch())
			encoded = appendInt64(encoded, contract.ExpiresAt().UnixNano())
			encoded = append(encoded, trafficHash[:]...)
			encoded = append(encoded, byte(destination.protocol))
			encoded = appendUint64(encoded, uint64(len(destination.destinationPortRanges)))
			for _, portRange := range destination.destinationPortRanges {
				encoded = appendUint16(encoded, portRange.First())
				encoded = appendUint16(encoded, portRange.Last())
			}
		}
	}
	if len(candidate.groupRules) > 0 {
		encoded = appendUint64(encoded, uint64(len(candidate.groupRules)))
		for _, rule := range candidate.groupRules {
			ruleID := publicid.ID(rule.ruleID).Bytes()
			encoded = append(encoded, ruleID[:]...)
			encoded = appendGroupRuleSide(encoded, rule.source)
			encoded = appendGroupRuleSide(encoded, rule.destination)
			encoded = append(encoded, byte(rule.protocol))
			encoded = appendUint64(encoded, uint64(len(rule.destinationPortRanges)))
			for _, portRange := range rule.destinationPortRanges {
				encoded = appendUint16(encoded, portRange.First())
				encoded = appendUint16(encoded, portRange.Last())
			}
		}
	}
	if len(candidate.routeRules) > 0 {
		encoded = appendRouteRules(encoded, candidate.routeRules)
	}
	if len(candidate.exitRules) > 0 {
		encoded = appendExitRules(encoded, candidate.exitRules)
	}
	if domain == policyHashDomainV8 || domain == policyHashDomainV9 {
		encoded = appendKubernetesGroups(encoded, candidate.groupRules)
	}
	if domain == policyHashDomainV9 {
		encoded = appendKubernetesAccess(encoded, candidate.groupRules)
		encoded = appendKubernetesProfiles(encoded, candidate.kubernetesProfiles)
	}
	return SemanticHash(sha256.Sum256(encoded))
}

// appendKubernetesAccess encodes, for each group rule in release order,
// whether it applies a profile and then the profile's ID and content, the
// namespaces with their lengths after a count, the cluster part, the mode and
// the report deadline in Unix milliseconds (0 when enforcing).
func appendKubernetesAccess(encoded []byte, rules []GroupRule) []byte {
	for _, rule := range rules {
		access := rule.kubernetesAccess
		if access.IsZero() {
			encoded = append(encoded, 0)
			continue
		}
		profileID := publicid.ID(access.profileID).Bytes()
		encoded = append(encoded, 1)
		encoded = append(encoded, profileID[:]...)
		encoded = append(encoded, access.profileHash[:]...)
		encoded = appendUint64(encoded, uint64(len(access.namespaces)))
		for _, namespace := range access.namespaces {
			encoded = appendUint64(encoded, uint64(len(namespace)))
			encoded = append(encoded, namespace...)
		}
		encoded = append(encoded, boolByte(access.clusterPart), boolByte(access.report))
		var until int64
		if access.report {
			until = access.reportUntil.UnixMilli()
		}
		encoded = appendInt64(encoded, until)
	}
	return encoded
}

// appendKubernetesProfiles encodes the release's profiles by ID after a
// count: each ID and content hash. The name is in the content; the
// description is not part of what the release grants.
func appendKubernetesProfiles(encoded []byte, profiles []KubernetesProfile) []byte {
	encoded = appendUint64(encoded, uint64(len(profiles)))
	for _, profile := range profiles {
		id := publicid.ID(profile.id).Bytes()
		encoded = append(encoded, id[:]...)
		encoded = append(encoded, profile.contentHash[:]...)
	}
	return encoded
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}

// CoversKubernetesProfiles reports whether any rule applies an access
// profile, so that the semantic hash is of domain v9 and covers them.
func (candidate Candidate) CoversKubernetesProfiles() bool {
	return slices.ContainsFunc(candidate.groupRules, func(rule GroupRule) bool {
		return !rule.kubernetesAccess.IsZero()
	})
}

// SemanticHashAs returns the hash a Core computes for the release when it
// covers Kubernetes groups only if groups, and profiles only if profiles:
// what the stored flags of a release say it was hashed as. It is
// SemanticHash when both hold.
func (candidate Candidate) SemanticHashAs(groups, profiles bool) SemanticHash {
	level := candidate.hashLevel()
	if !profiles && level == hashProfiles {
		level = hashGroups
	}
	if !groups {
		level = hashBeforeGroups
	}
	return hashCandidateWith(candidate, level)
}

// HashesAs reports whether hash is the candidate's own, or one a Core of an
// earlier era computed for it: without profiles, or without groups.
func (candidate Candidate) HashesAs(hash SemanticHash) bool {
	switch candidate.hashLevel() {
	case hashProfiles:
		return hash == candidate.semanticHash || hash == hashCandidateWith(candidate, hashGroups) ||
			hash == hashCandidateWith(candidate, hashBeforeGroups)
	case hashGroups:
		return hash == candidate.semanticHash || hash == hashCandidateWith(candidate, hashBeforeGroups)
	default:
		return hash == candidate.semanticHash
	}
}

// appendKubernetesGroups encodes, for each group rule in release order, the
// count of its Kubernetes groups and each group with its length.
func appendKubernetesGroups(encoded []byte, rules []GroupRule) []byte {
	for _, rule := range rules {
		encoded = appendUint64(encoded, uint64(len(rule.kubernetesGroups)))
		for _, group := range rule.kubernetesGroups {
			encoded = appendUint64(encoded, uint64(len(group)))
			encoded = append(encoded, group...)
		}
	}
	return encoded
}

// CoversKubernetesGroups reports whether any rule names Kubernetes groups,
// so that the semantic hash is of domain v8 and covers them.
func (candidate Candidate) CoversKubernetesGroups() bool {
	return slices.ContainsFunc(candidate.groupRules, func(rule GroupRule) bool {
		return rule.kubernetesGroups != nil
	})
}

// LegacySemanticHash returns the hash a Core before K1a3 computes for the
// release: without Kubernetes groups. It equals SemanticHash when no rule
// names any.
func (candidate Candidate) LegacySemanticHash() SemanticHash {
	return hashCandidateWith(candidate, hashBeforeGroups)
}

// presentSections tags which optional sections follow the Device pairs, so
// that from v6 on no two candidates encode to the same bytes: each section
// is then known to be there before its count is read.
func presentSections(candidate Candidate) byte {
	var present byte
	for bit, there := range []bool{
		len(candidate.resourceDestinations) > 0 || len(candidate.resourceGroupDestinations) > 0,
		len(candidate.resourceGroupDestinations) > 0,
		len(candidate.importedResourceDestinations) > 0,
		len(candidate.groupRules) > 0,
	} {
		if there {
			present |= 1 << bit
		}
	}
	return present
}

// appendRouteRules encodes each route rule after a count: rule ID, source
// side, Site ID, prefixes (family, address, length), protocol and ports.
func appendRouteRules(encoded []byte, rules []RouteRule) []byte {
	encoded = appendUint64(encoded, uint64(len(rules)))
	for _, rule := range rules {
		ruleID := publicid.ID(rule.ruleID).Bytes()
		siteID := publicid.ID(rule.siteID).Bytes()
		encoded = append(encoded, ruleID[:]...)
		encoded = appendGroupRuleSide(encoded, rule.source)
		encoded = append(encoded, siteID[:]...)
		encoded = appendUint64(encoded, uint64(len(rule.prefixes)))
		for _, prefix := range rule.prefixes {
			address := prefix.Addr().AsSlice()
			encoded = append(encoded, byte(len(address))) //nolint:gosec // G115: 4 or 16
			encoded = append(encoded, address...)
			encoded = append(encoded, byte(prefix.Bits())) //nolint:gosec // G115: at most 128
		}
		encoded = append(encoded, byte(rule.protocol))
		encoded = appendUint64(encoded, uint64(len(rule.destinationPortRanges)))
		for _, portRange := range rule.destinationPortRanges {
			encoded = appendUint16(encoded, portRange.First())
			encoded = appendUint16(encoded, portRange.Last())
		}
	}
	return encoded
}

// appendGroupRuleSide tags a rule side with its kind (Device 1, Device
// Group 2, Identity Group 3, tag 4) before its identity, so selectors with
// equal bytes differ. Kinds 1 and 2 keep the encoding of schema 120.
func appendGroupRuleSide(output []byte, side RuleSide) []byte {
	id := side.id.Bytes()
	return append(append(output, byte(side.kind)), id[:]...)
}

func appendUint16(output []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(output, encoded[:]...)
}

func appendUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}

func appendInt64(output []byte, value int64) []byte {
	var encoded [binary.MaxVarintLen64]byte
	length := binary.PutVarint(encoded[:], value)
	return append(output, encoded[:length]...)
}
