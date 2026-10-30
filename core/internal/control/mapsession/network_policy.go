package mapsession

import (
	"errors"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// SelectorKind names what one side of a Network policy rule selects.
type SelectorKind uint8

const (
	// SelectorUnknown is the invalid zero value.
	SelectorUnknown SelectorKind = iota
	// SelectorDevice selects one Device by its internal reference.
	SelectorDevice
	// SelectorDeviceGroup selects a Device Group's members.
	SelectorDeviceGroup
	// SelectorIdentityGroup selects the Devices of an Identity Group's
	// members (source side only).
	SelectorIdentityGroup
	// SelectorDeviceTag selects the Devices carrying a tag.
	SelectorDeviceTag
)

// ErrInvalidNetworkPolicy reports incomplete or inconsistent policy evidence.
var ErrInvalidNetworkPolicy = errors.New("map session: invalid network policy")

// NetworkPolicyRule is one rule of a Network's active release, each side
// named by selector: a Device-to-Device compiled rule has two Device sides.
type NetworkPolicyRule struct {
	ID              policy.RuleID
	SourceKind      SelectorKind
	SourceRef       int64
	DestinationKind SelectorKind
	DestinationRef  int64
	Protocol        policy.Protocol
	Ports           []policy.PortRange
	// KubernetesGroups are the groups a rule to a cluster's own Device
	// Group grants, sorted; nil for any other rule (K1a3).
	KubernetesGroups []string
	// KubernetesAccess narrows those groups to a profile (K2); nil grants
	// them whole.
	KubernetesAccess *KubernetesRuleAccess
}

// SelectorMember places one Device in one selector, until ValidUntil when
// set (an expiring Workspace membership behind an Identity Group).
type SelectorMember struct {
	Kind       SelectorKind
	Selector   int64
	Device     int64
	ValidUntil time.Time
}

// PolicyDevice is a Device the policy treats as live until ExpiresAt.
type PolicyDevice struct {
	Device    int64
	NodeID    node.ID
	ExpiresAt time.Time
}

// NetworkPolicyParams is one Network's policy at one policy revision.
type NetworkPolicyParams struct {
	Scope         network.Scope
	Revision      int64
	ReleaseActive bool
	Rules         []NetworkPolicyRule
	Members       []SelectorMember
	Devices       []PolicyDevice
	// Subnet routes (mtcp-v1 §7.6), when the deployment routes subnets:
	// the active Sites, their routers, the active release's rules to Sites,
	// the route revision consumers see as each Site's generation, and the
	// peer limit a router's consumers are cut at. All empty: none.
	RouteRevision  int64
	RoutePeerLimit int
	Sites          []RouteSite
	RouteRouters   []RouteRouter
	RouteRules     []RouteRule
	// Exit Pools (mtcp-v1 §7.7), when the deployment has exit nodes: the
	// active pools, their exit nodes and the active release's rules to
	// pools, at the same route revision and peer limit. All empty: none.
	ExitPools []ExitPool
	ExitNodes []ExitNode
	ExitRules []ExitRule
	// DNS zones (DNS design D1), when the deployment has them: the active
	// forward zones and their resolvers, at the same peer limit. Whether a
	// rule admits a Device to a resolver comes from Rules.
	DNSZones []DNSZone
	// DNS names (DNS design D2) of those zones; whether a Device sees a
	// name that points at a Device comes from Rules.
	DNSNames []DNSName
	// DNSUnmanagedGroups are the Device Groups whose Devices get no DNS
	// configuration in their maps (DNS design D5b, schema 221).
	DNSUnmanagedGroups []int64
	// KubernetesSources are, for a Network that has a Kubernetes cluster,
	// what each Device's Kubernetes access rests on (K1a3); none for other
	// Networks.
	KubernetesSources []KubernetesSource
	// KubernetesProfiles are the profiles the release's rules apply (K2),
	// each checked against its hash.
	KubernetesProfiles []KubernetesProfile
}

// NetworkPolicy is one Network's packet policy at selector level, shared by
// every Device's map. For expands it for one Device in O(rules + output)
// without pairing every Device of a group with every other.
//
// Its zero value is invalid.
type NetworkPolicy struct {
	inner *networkPolicy
}

type selectorKey struct {
	kind SelectorKind
	id   int64
}

type selectorEntry struct {
	device     int64
	validUntil time.Time
}

type networkPolicy struct {
	scope         network.Scope
	revision      int64
	releaseActive bool
	rules         []NetworkPolicyRule
	members       map[selectorKey][]selectorEntry
	memberOf      map[int64]map[selectorKey]time.Time // device -> selector -> valid until
	devices       map[int64]PolicyDevice
	byNode        map[node.ID]int64
	changesAt     time.Time // earliest Device expiry or membership deadline
	// memberList and deviceList keep the evidence as read, for Equal.
	memberList []SelectorMember
	deviceList []PolicyDevice
	// routes holds the Network's subnet routes; nil: none.
	routes *routeIndex
	// sources indexes KubernetesSources by Device; sourceList keeps them as
	// read, for Equal.
	sources    map[int64]KubernetesSource
	sourceList []KubernetesSource
	// profiles indexes KubernetesProfiles by hash; profileList keeps them as
	// read, for Equal.
	profiles    map[[32]byte]KubernetesProfile
	profileList []KubernetesProfile
}

// NewNetworkPolicy validates and indexes one Network's policy.
func NewNetworkPolicy(params NetworkPolicyParams) (NetworkPolicy, error) {
	if !params.Scope.IsValid() || params.Revision <= 0 {
		return NetworkPolicy{}, ErrInvalidNetworkPolicy
	}
	inner := &networkPolicy{
		scope: params.Scope, revision: params.Revision, releaseActive: params.ReleaseActive,
		rules:      cloneNetworkPolicyRules(params.Rules),
		members:    make(map[selectorKey][]selectorEntry),
		memberOf:   make(map[int64]map[selectorKey]time.Time),
		devices:    make(map[int64]PolicyDevice, len(params.Devices)),
		byNode:     make(map[node.ID]int64, len(params.Devices)),
		memberList: slices.Clone(params.Members),
		deviceList: slices.Clone(params.Devices),
		sources:    make(map[int64]KubernetesSource, len(params.KubernetesSources)),
		sourceList: slices.Clone(params.KubernetesSources),
	}
	profiles, ok := indexKubernetesProfiles(params.KubernetesProfiles)
	if !ok {
		return NetworkPolicy{}, ErrInvalidNetworkPolicy
	}
	inner.profiles, inner.profileList = profiles, slices.Clone(params.KubernetesProfiles)
	for _, source := range params.KubernetesSources {
		if _, duplicate := inner.sources[source.Device]; duplicate || !source.valid() {
			return NetworkPolicy{}, ErrInvalidNetworkPolicy
		}
		inner.sources[source.Device] = source
	}
	if !params.ReleaseActive && len(params.Rules) != 0 {
		return NetworkPolicy{}, ErrInvalidNetworkPolicy
	}
	for _, device := range params.Devices {
		if device.Device <= 0 || !device.NodeID.IsValid() || device.ExpiresAt.IsZero() {
			return NetworkPolicy{}, ErrInvalidNetworkPolicy
		}
		if _, duplicate := inner.devices[device.Device]; duplicate {
			return NetworkPolicy{}, ErrInvalidNetworkPolicy
		}
		if _, duplicate := inner.byNode[device.NodeID]; duplicate {
			return NetworkPolicy{}, ErrInvalidNetworkPolicy
		}
		inner.devices[device.Device] = device
		inner.byNode[device.NodeID] = device.Device
		inner.noteChange(device.ExpiresAt)
	}
	for _, member := range params.Members {
		if !member.Kind.selectsMembers() || member.Selector <= 0 || member.Device <= 0 {
			return NetworkPolicy{}, ErrInvalidNetworkPolicy
		}
		key := selectorKey{kind: member.Kind, id: member.Selector}
		inner.members[key] = append(inner.members[key], selectorEntry{device: member.Device, validUntil: member.ValidUntil})
		if inner.memberOf[member.Device] == nil {
			inner.memberOf[member.Device] = make(map[selectorKey]time.Time)
		}
		if _, duplicate := inner.memberOf[member.Device][key]; duplicate {
			return NetworkPolicy{}, ErrInvalidNetworkPolicy
		}
		inner.memberOf[member.Device][key] = member.ValidUntil
		if !member.ValidUntil.IsZero() {
			inner.noteChange(member.ValidUntil)
		}
	}
	for _, rule := range inner.rules {
		if !rule.ID.IsValid() || !rule.SourceKind.valid() || !rule.DestinationKind.valid() ||
			rule.DestinationKind == SelectorIdentityGroup || rule.SourceRef <= 0 || rule.DestinationRef <= 0 ||
			!validRuleKubernetesGroups(rule) || rule.KubernetesAccess != nil && rule.KubernetesGroups == nil ||
			!validKubernetesRuleAccess(rule.KubernetesAccess, inner.profiles) {
			return NetworkPolicy{}, ErrInvalidNetworkPolicy
		}
	}
	routes, ok := newRouteIndex(params, func(kind SelectorKind, ref int64) []int64 {
		entries := inner.members[selectorKey{kind: kind, id: ref}]
		devices := make([]int64, len(entries))
		for index, entry := range entries {
			devices[index] = entry.device
		}
		return devices
	}, func(device int64) []selectorKey {
		keys := make([]selectorKey, 0, len(inner.memberOf[device])+1)
		for key := range inner.memberOf[device] {
			keys = append(keys, key)
		}
		return keys
	})
	if !ok || (!params.ReleaseActive && (len(params.RouteRules) != 0 || len(params.ExitRules) != 0)) {
		return NetworkPolicy{}, ErrInvalidNetworkPolicy
	}
	inner.routes = routes
	return NetworkPolicy{inner: inner}, nil
}

func (inner *networkPolicy) noteChange(at time.Time) {
	if inner.changesAt.IsZero() || at.Before(inner.changesAt) {
		inner.changesAt = at
	}
}

// IsValid reports whether the policy was built by NewNetworkPolicy.
func (networkPolicy NetworkPolicy) IsValid() bool { return networkPolicy.inner != nil }

// Equal reports whether two policies hold the same evidence, read in the
// same order (a reread of an unchanged Network).
func (networkPolicy NetworkPolicy) Equal(other NetworkPolicy) bool {
	left, right := networkPolicy.inner, other.inner
	if left == nil || right == nil {
		return left == right
	}
	if left == right {
		return true
	}
	return left.scope == right.scope && left.revision == right.revision && left.releaseActive == right.releaseActive &&
		slices.EqualFunc(left.rules, right.rules, func(first, second NetworkPolicyRule) bool {
			return first.ID == second.ID && first.SourceKind == second.SourceKind && first.SourceRef == second.SourceRef &&
				first.DestinationKind == second.DestinationKind && first.DestinationRef == second.DestinationRef &&
				first.Protocol == second.Protocol && slices.Equal(first.Ports, second.Ports) &&
				slices.Equal(first.KubernetesGroups, second.KubernetesGroups) &&
				first.KubernetesAccess.equal(second.KubernetesAccess)
		}) &&
		slices.EqualFunc(left.memberList, right.memberList, func(first, second SelectorMember) bool {
			return first.Kind == second.Kind && first.Selector == second.Selector && first.Device == second.Device &&
				first.ValidUntil.Equal(second.ValidUntil)
		}) &&
		slices.EqualFunc(left.deviceList, right.deviceList, func(first, second PolicyDevice) bool {
			return first.Device == second.Device && first.NodeID == second.NodeID && first.ExpiresAt.Equal(second.ExpiresAt)
		}) && left.routes.equal(right.routes) && equalKubernetesSources(left.sourceList, right.sourceList) &&
		slices.EqualFunc(left.profileList, right.profileList, func(first, second KubernetesProfile) bool {
			return first.Hash == second.Hash && first.ID == second.ID
		})
}

// RoutesFor returns self's subnet routes at time now: the Sites it may reach
// as a consumer and those it serves as a router (mtcp-v1 §7.6). Like For, it
// is stable until ChangesAt. A Device the policy does not treat as live gets
// none.
func (networkPolicy NetworkPolicy) RoutesFor(self node.ID, now time.Time) RouteView {
	inner := networkPolicy.inner
	if inner == nil {
		return RouteView{}
	}
	device, known := inner.byNode[self]
	if !known {
		return RouteView{}
	}
	return inner.routesFor(device, now)
}

// Revision returns the policy revision.
func (networkPolicy NetworkPolicy) Revision() int64 {
	if networkPolicy.inner == nil {
		return 0
	}
	return networkPolicy.inner.revision
}

// ChangesAt returns the earliest time a Device's liveness or a selector
// membership in the policy lapses (zero when none does); the expansion of
// For is only stable before it.
func (networkPolicy NetworkPolicy) ChangesAt() time.Time {
	if networkPolicy.inner == nil {
		return time.Time{}
	}
	return networkPolicy.inner.changesAt
}

// For returns self's Node-reduced packet policy at time now: every rule with
// self on one side and a live Device on the other, both sides live, exactly
// as the per-Device read returns them (group rules expanded only around
// self). limit bounds the rules, as the per-Device read does.
func (networkPolicy NetworkPolicy) For(self node.ID, now time.Time, limit int) (policy.Snapshot, error) {
	inner := networkPolicy.inner
	if inner == nil || !self.IsValid() || limit <= 0 {
		return policy.Snapshot{}, ErrInvalidNetworkPolicy
	}
	if !inner.releaseActive {
		if inner.revision != 1 {
			return policy.Snapshot{}, ErrInvalidNetworkPolicy
		}
		return policy.NewSnapshot(policy.SnapshotParams{Scope: inner.scope, Revision: inner.revision, Rules: []policy.Rule{}})
	}
	rules := make([]policy.Rule, 0, 8)
	selfDevice, known := inner.byNode[self]
	if known && inner.live(selfDevice, now) {
		var err error
		if rules, err = inner.expand(selfDevice, now, limit); err != nil {
			return policy.Snapshot{}, err
		}
	}
	return policy.NewSnapshot(policy.SnapshotParams{Scope: inner.scope, Revision: inner.revision, Rules: rules})
}

func (inner *networkPolicy) expand(self int64, now time.Time, limit int) ([]policy.Rule, error) {
	rules := make([]policy.Rule, 0, 8)
	emit := func(rule NetworkPolicyRule, source, destination int64) error {
		if source == destination || !inner.live(source, now) || !inner.live(destination, now) {
			return nil
		}
		if len(rules) == limit {
			return ErrPacketPolicyLimit
		}
		value, err := policy.NewRule(policy.RuleParams{
			ID: rule.ID, Scope: inner.scope, SourceNodeID: inner.devices[source].NodeID,
			DestinationNodeID: inner.devices[destination].NodeID, Protocol: rule.Protocol,
			DestinationPortRanges: rule.Ports,
		})
		if err != nil {
			return errors.Join(ErrInvalidNetworkPolicy, err)
		}
		rules = append(rules, value)
		return nil
	}
	for _, rule := range inner.rules {
		if inner.selects(rule.SourceKind, rule.SourceRef, self, now) {
			if err := inner.eachSelected(rule.DestinationKind, rule.DestinationRef, now, func(destination int64) error {
				return emit(rule, self, destination)
			}); err != nil {
				return nil, err
			}
		}
		if inner.selects(rule.DestinationKind, rule.DestinationRef, self, now) {
			if err := inner.eachSelected(rule.SourceKind, rule.SourceRef, now, func(source int64) error {
				return emit(rule, source, self)
			}); err != nil {
				return nil, err
			}
		}
	}
	return rules, nil
}

// live reports whether the policy treats device as live at now.
func (inner *networkPolicy) live(device int64, now time.Time) bool {
	entry, found := inner.devices[device]
	return found && now.Before(entry.ExpiresAt)
}

// selects reports whether one rule side selects device at now.
func (inner *networkPolicy) selects(kind SelectorKind, ref, device int64, now time.Time) bool {
	if kind == SelectorDevice {
		return ref == device
	}
	validUntil, member := inner.memberOf[device][selectorKey{kind: kind, id: ref}]
	return member && (validUntil.IsZero() || now.Before(validUntil))
}

// eachSelected visits every Device one rule side selects at now.
func (inner *networkPolicy) eachSelected(kind SelectorKind, ref int64, now time.Time, visit func(int64) error) error {
	if kind == SelectorDevice {
		return visit(ref)
	}
	for _, entry := range inner.members[selectorKey{kind: kind, id: ref}] {
		if entry.validUntil.IsZero() || now.Before(entry.validUntil) {
			if err := visit(entry.device); err != nil {
				return err
			}
		}
	}
	return nil
}

func (kind SelectorKind) valid() bool {
	return kind == SelectorDevice || kind.selectsMembers()
}

func (kind SelectorKind) selectsMembers() bool {
	return kind == SelectorDeviceGroup || kind == SelectorIdentityGroup || kind == SelectorDeviceTag
}

func cloneNetworkPolicyRules(rules []NetworkPolicyRule) []NetworkPolicyRule {
	cloned := make([]NetworkPolicyRule, len(rules))
	for index, rule := range rules {
		rule.Ports = append([]policy.PortRange(nil), rule.Ports...)
		rule.KubernetesGroups = slices.Clone(rule.KubernetesGroups)
		rule.KubernetesAccess = rule.KubernetesAccess.clone()
		cloned[index] = rule
	}
	return cloned
}
