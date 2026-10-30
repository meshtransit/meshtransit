// Package compilation resolves typed policy intent into immutable Node-level artifacts.
package compilation

import (
	"errors"
	"net/netip"
	"slices"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/site"
)

var (
	// ErrInvalidRequest reports malformed, ambiguous, or over-limit policy intent.
	ErrInvalidRequest = errors.New("policy compilation: invalid request")
	// ErrResourceConflict reports inactive or changed Resource authority.
	ErrResourceConflict = errors.New("policy compilation: resource conflict")
	// ErrForbidden hides which Resource catalog authorization prerequisite failed.
	ErrForbidden = errors.New("policy compilation: forbidden")
	// ErrUnavailable reports an unavailable authoritative dependency.
	ErrUnavailable = errors.New("policy compilation: unavailable")
)

// RuleIntentParams contains one atomic Access Rule before destination resolution.
// The source is one Device, Device Group, Identity Group or tag. A source
// other than a Device takes a Device, Device Group or tag destination only;
// a tag destination needs no particular source.
type RuleIntentParams struct {
	ID                            policy.RuleID
	Scope                         network.Scope
	SourceNodeID                  node.ID
	SourceGroupID                 devicegroup.ID
	SourceIdentityGroupID         identitygroup.ID
	SourceTagID                   devicetag.ID
	DestinationNodeID             node.ID
	DestinationDeviceGroupID      devicegroup.ID
	DestinationTagID              devicetag.ID
	DestinationResourceID         resource.ID
	DestinationGroupID            resource.GroupID
	DestinationImportedResourceID sharing.ImportedResourceID
	// DestinationSiteID selects a Site; DestinationPrefixes narrows it to
	// some of its prefixes (empty for the whole Site).
	DestinationSiteID   site.ID
	DestinationPrefixes []netip.Prefix
	// DestinationExitPoolID selects the Internet through an Exit Pool.
	DestinationExitPoolID exitpool.ID
	// DestinationKubernetesClusterID selects every replica of a Kubernetes
	// cluster, through the cluster's own Device Group, on TCP 443 only.
	DestinationKubernetesClusterID kubecluster.ID
	// KubernetesGroups are the groups a rule to a cluster grants, in any
	// order (K1a3). Nil keeps the groups the rule has in the release the
	// request replaces; an empty list is refused.
	KubernetesGroups []string
	// KubernetesAccess is how a rule to a cluster applies its groups (K2):
	// in full or through a profile. Nil keeps what the rule has in the
	// release the request replaces, whatever KubernetesGroups says.
	KubernetesAccess      *KubernetesAccessIntent
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// RuleIntent is one immutable Access Rule with exactly one typed destination.
type RuleIntent struct {
	id                            policy.RuleID
	scope                         network.Scope
	sourceNodeID                  node.ID
	sourceGroupID                 devicegroup.ID
	sourceIdentityGroupID         identitygroup.ID
	sourceTagID                   devicetag.ID
	destinationNodeID             node.ID
	destinationDeviceGroupID      devicegroup.ID
	destinationTagID              devicetag.ID
	destinationResourceID         resource.ID
	destinationGroupID            resource.GroupID
	destinationImportedResourceID sharing.ImportedResourceID
	destinationSiteID             site.ID
	destinationPrefixes           []netip.Prefix
	destinationExitPoolID         exitpool.ID
	destinationCluster            kubecluster.ID
	kubernetesGroups              []string
	kubernetesAccess              *KubernetesAccessIntent
	protocol                      policy.Protocol
	destinationPortRanges         []policy.PortRange
}

// NewRuleIntent validates one Device or Resource destination without resolving it.
func NewRuleIntent(params RuleIntentParams) (RuleIntent, error) {
	intent := RuleIntent{
		id: params.ID, scope: params.Scope, sourceNodeID: params.SourceNodeID,
		sourceGroupID:                 params.SourceGroupID,
		sourceIdentityGroupID:         params.SourceIdentityGroupID,
		sourceTagID:                   params.SourceTagID,
		destinationNodeID:             params.DestinationNodeID,
		destinationDeviceGroupID:      params.DestinationDeviceGroupID,
		destinationTagID:              params.DestinationTagID,
		destinationResourceID:         params.DestinationResourceID,
		destinationGroupID:            params.DestinationGroupID,
		destinationImportedResourceID: params.DestinationImportedResourceID,
		destinationSiteID:             params.DestinationSiteID,
		destinationPrefixes:           slices.Clone(params.DestinationPrefixes),
		destinationExitPoolID:         params.DestinationExitPoolID,
		destinationCluster:            params.DestinationKubernetesClusterID,
		kubernetesGroups:              sortedKubernetesGroups(params.KubernetesGroups),
		kubernetesAccess:              params.KubernetesAccess.clone(),
		protocol:                      params.Protocol, destinationPortRanges: slices.Clone(params.DestinationPortRanges),
	}
	if !intent.IsValid() {
		return RuleIntent{}, ErrInvalidRequest
	}
	return intent, nil
}

// ID returns the stable Access Rule identity.
func (intent RuleIntent) ID() policy.RuleID { return intent.id }

// Scope returns the exact Workspace-qualified Network scope.
func (intent RuleIntent) Scope() network.Scope { return intent.scope }

// SourceNodeID returns the initiating Device identity, when the source is a Device.
func (intent RuleIntent) SourceNodeID() node.ID { return intent.sourceNodeID }

// SourceGroupID returns the initiating Device Group, when the source is a group.
func (intent RuleIntent) SourceGroupID() devicegroup.ID { return intent.sourceGroupID }

// DestinationDeviceGroupID returns the Device Group destination, when selected.
func (intent RuleIntent) DestinationDeviceGroupID() devicegroup.ID {
	return intent.destinationDeviceGroupID
}

// SourceIdentityGroupID returns the initiating Identity Group, when the source is one.
func (intent RuleIntent) SourceIdentityGroupID() identitygroup.ID {
	return intent.sourceIdentityGroupID
}

// SourceTagID returns the initiating tag, when the source is a tag.
func (intent RuleIntent) SourceTagID() devicetag.ID { return intent.sourceTagID }

// DestinationTagID returns the tag destination, when selected.
func (intent RuleIntent) DestinationTagID() devicetag.ID { return intent.destinationTagID }

// SelectsDeviceGroup reports whether either side is a group or a tag, so the
// rule is resolved from membership, ownership and tags when maps are built
// instead of compiled to Device pairs. A Site rule is a route rule instead,
// and an Exit Pool rule an exit rule.
func (intent RuleIntent) SelectsDeviceGroup() bool {
	if intent.destinationSiteID.IsValid() || intent.destinationExitPoolID.IsValid() {
		return false
	}
	return intent.sourceGroupID.IsValid() || intent.destinationDeviceGroupID.IsValid() ||
		intent.sourceIdentityGroupID.IsValid() || intent.sourceTagID.IsValid() || intent.destinationTagID.IsValid() ||
		intent.destinationCluster.IsValid()
}

// KubernetesGroups returns the sorted groups a rule to a cluster names, nil
// when it names none and keeps those it has.
func (intent RuleIntent) KubernetesGroups() []string { return slices.Clone(intent.kubernetesGroups) }

// sortedKubernetesGroups sorts a copy; nil stays nil and an empty list stays
// empty, for IsValid to refuse.
func sortedKubernetesGroups(groups []string) []string {
	if groups == nil {
		return nil
	}
	sorted := slices.Clone(groups)
	slices.Sort(sorted)
	return sorted
}

// validKubernetesGroups reports nil, or 1 to 16 distinct sorted groups.
func validKubernetesGroups(groups []string) bool {
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

// DestinationKubernetesClusterID returns the Kubernetes cluster destination,
// when selected.
func (intent RuleIntent) DestinationKubernetesClusterID() kubecluster.ID {
	return intent.destinationCluster
}

// WithKubernetesCluster returns the intent naming the cluster in place of
// the cluster's own Device Group it names, for a reader who knows that group
// is the cluster's.
func (intent RuleIntent) WithKubernetesCluster(cluster kubecluster.ID) (RuleIntent, error) {
	if !intent.destinationDeviceGroupID.IsValid() {
		return RuleIntent{}, ErrInvalidRequest
	}
	named := intent
	named.destinationDeviceGroupID, named.destinationCluster = devicegroup.ID{}, cluster
	named.destinationPrefixes = slices.Clone(intent.destinationPrefixes)
	named.destinationPortRanges = slices.Clone(intent.destinationPortRanges)
	named.kubernetesGroups = slices.Clone(intent.kubernetesGroups)
	named.kubernetesAccess = intent.kubernetesAccess.clone()
	if !named.IsValid() {
		return RuleIntent{}, ErrInvalidRequest
	}
	return named, nil
}

// WithKubernetesGroups returns the intent to a cluster naming groups, for a
// reader of a release that holds them; nil names none.
func (intent RuleIntent) WithKubernetesGroups(groups []string) (RuleIntent, error) {
	named := intent
	named.destinationPrefixes = slices.Clone(intent.destinationPrefixes)
	named.destinationPortRanges = slices.Clone(intent.destinationPortRanges)
	named.kubernetesGroups = sortedKubernetesGroups(groups)
	named.kubernetesAccess = intent.kubernetesAccess.clone()
	if !named.IsValid() {
		return RuleIntent{}, ErrInvalidRequest
	}
	return named, nil
}

// DestinationNodeID returns the direct Device destination, when selected.
func (intent RuleIntent) DestinationNodeID() node.ID { return intent.destinationNodeID }

// DestinationResourceID returns the Resource destination, when selected.
func (intent RuleIntent) DestinationResourceID() resource.ID {
	return intent.destinationResourceID
}

// DestinationGroupID returns the Resource Group destination, when selected.
func (intent RuleIntent) DestinationGroupID() resource.GroupID {
	return intent.destinationGroupID
}

// DestinationImportedResourceID returns the consumer-local shared selector, when selected.
func (intent RuleIntent) DestinationImportedResourceID() sharing.ImportedResourceID {
	return intent.destinationImportedResourceID
}

// DestinationSiteID returns the Site destination, when selected.
func (intent RuleIntent) DestinationSiteID() site.ID { return intent.destinationSiteID }

// DestinationPrefixes returns the caller-owned part of the Site the rule
// asks for; empty means the whole Site.
func (intent RuleIntent) DestinationPrefixes() []netip.Prefix {
	return slices.Clone(intent.destinationPrefixes)
}

// DestinationExitPoolID returns the Exit Pool destination, when selected.
func (intent RuleIntent) DestinationExitPoolID() exitpool.ID { return intent.destinationExitPoolID }

// Protocol returns the explicit packet protocol.
func (intent RuleIntent) Protocol() policy.Protocol { return intent.protocol }

// DestinationPortRanges returns caller-owned transport intervals.
func (intent RuleIntent) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(intent.destinationPortRanges)
}

// IsValid reports whether the intent has exactly one source and one typed
// destination, and a group or tag rule only between Devices, Device Groups,
// Identity Groups (as a source) and tags.
func (intent RuleIntent) IsValid() bool {
	hasDevice := intent.destinationNodeID.IsValid()
	hasDeviceGroup := intent.destinationDeviceGroupID.IsValid()
	hasTag := intent.destinationTagID.IsValid()
	hasResource := intent.destinationResourceID.IsValid()
	hasGroup := intent.destinationGroupID.IsValid()
	hasImported := intent.destinationImportedResourceID.IsValid()
	hasSite := intent.destinationSiteID.IsValid()
	hasExitPool := intent.destinationExitPoolID.IsValid()
	hasCluster := intent.destinationCluster.IsValid()
	if !intent.id.IsValid() || !intent.scope.IsValid() ||
		boolCount(intent.sourceNodeID.IsValid(), intent.sourceGroupID.IsValid(),
			intent.sourceIdentityGroupID.IsValid(), intent.sourceTagID.IsValid()) != 1 ||
		boolCount(hasDevice, hasDeviceGroup, hasTag, hasResource, hasGroup, hasImported, hasSite,
			hasExitPool, hasCluster) != 1 ||
		!intent.protocol.IsValid() || intent.destinationPortRanges == nil ||
		(!hasSite && len(intent.destinationPrefixes) > 0) ||
		len(intent.destinationPrefixes) > site.MaximumPrefixesPerSite ||
		!validKubernetesGroups(intent.kubernetesGroups) || intent.kubernetesGroups != nil && !hasCluster ||
		intent.kubernetesAccess != nil && (!hasCluster || !intent.kubernetesAccess.IsValid()) {
		return false
	}
	if hasSite || hasExitPool {
		// Any source selector; a Site's prefixes are checked against the Site
		// when it is resolved, and an Exit Pool takes none.
		_, valid := policy.CanonicalTraffic(intent.protocol, intent.destinationPortRanges)
		return valid
	}
	if intent.SelectsDeviceGroup() {
		if !hasDevice && !hasDeviceGroup && !hasTag && !hasCluster {
			return false
		}
		ports, valid := policy.CanonicalTraffic(intent.protocol, intent.destinationPortRanges)
		return valid && (!hasCluster || policy.IsKubernetesTraffic(intent.protocol, ports))
	}
	if hasDevice {
		_, err := policy.NewRule(policy.RuleParams{
			ID: intent.id, Scope: intent.scope, SourceNodeID: intent.sourceNodeID,
			DestinationNodeID: intent.destinationNodeID, Protocol: intent.protocol,
			DestinationPortRanges: intent.destinationPortRanges,
		})
		return err == nil
	}
	if len(intent.destinationPortRanges) > policy.MaximumPortRangesPerRule {
		return false
	}
	if intent.protocol == policy.ProtocolICMP {
		return len(intent.destinationPortRanges) == 0
	}
	if len(intent.destinationPortRanges) == 0 {
		return false
	}
	for _, portRange := range intent.destinationPortRanges {
		if portRange.First() == 0 || portRange.Last() < portRange.First() {
			return false
		}
	}
	return true
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

// RequestParams contains one complete policy compilation request.
type RequestParams struct {
	Scope    network.Scope
	Revision int64
	Rules    []RuleIntent
	// KubernetesProfiles are every access profile of the release (K2). Nil
	// keeps those of the release the request replaces; empty removes them.
	KubernetesProfiles []publication.KubernetesProfile
}

// Request is immutable typed policy intent for one successor revision.
type Request struct {
	scope              network.Scope
	revision           int64
	rules              []RuleIntent
	kubernetesProfiles []publication.KubernetesProfile
}

// NewRequest validates a bounded rule set with unique stable Access Rule IDs.
func NewRequest(params RequestParams) (Request, error) {
	request := Request{
		scope: params.Scope, revision: params.Revision, rules: slices.Clone(params.Rules),
		kubernetesProfiles: cloneProfiles(params.KubernetesProfiles),
	}
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// Scope returns the exact compilation scope.
func (request Request) Scope() network.Scope { return request.scope }

// Revision returns the successor policy revision.
func (request Request) Revision() int64 { return request.revision }

// Rules returns caller-owned immutable rule intents.
func (request Request) Rules() []RuleIntent { return slices.Clone(request.rules) }

// KubernetesProfiles returns the release's access profiles, nil when the
// request keeps those of the release it replaces.
func (request Request) KubernetesProfiles() []publication.KubernetesProfile {
	return cloneProfiles(request.kubernetesProfiles)
}

// IsValid reports whether every rule is exact-scoped, bounded, and uniquely identified.
func (request Request) IsValid() bool {
	if !request.scope.IsValid() || request.revision <= 1 || request.rules == nil ||
		len(request.rules) > policy.MaximumRules || !validRequestProfiles(request.kubernetesProfiles) {
		return false
	}
	seen := make(map[policy.RuleID]struct{}, len(request.rules))
	for _, rule := range request.rules {
		if !rule.IsValid() || rule.scope != request.scope {
			return false
		}
		if _, duplicate := seen[rule.id]; duplicate {
			return false
		}
		seen[rule.id] = struct{}{}
	}
	return true
}
