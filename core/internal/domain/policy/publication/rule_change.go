package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"strings"

	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
)

// Rule fingerprints let a publication say which Access Rules it adds,
// removes or changes relative to the release it replaces. Core computes them
// from the candidate and keeps them with the release, so the comparison runs
// here instead of over compiled rows in the database.

const (
	// RuleFingerprintSize is the encoded size of one rule: its ID, its
	// destination kind and ID, and a 16-byte digest of the rule as written.
	RuleFingerprintSize = 16 + 1 + 16 + 16
	// MaximumListedRuleChanges bounds the rules a change summary names; the
	// counts always cover every rule.
	MaximumListedRuleChanges = 20

	ruleFingerprintFormat     = 1
	ruleFingerprintHeaderSize = 1 + 4
)

// ErrInvalidRuleFingerprints reports fingerprints that do not decode, or a
// candidate whose parts give one rule two destinations.
var ErrInvalidRuleFingerprints = errors.New("policy publication: invalid rule fingerprints")

// DestinationKind names what an Access Rule's destination selects.
type DestinationKind uint8

const (
	// DestinationUnknown is invalid.
	DestinationUnknown DestinationKind = iota
	// DestinationDevice is one Device.
	DestinationDevice
	// DestinationDeviceGroup is a Network Device Group.
	DestinationDeviceGroup
	// DestinationDeviceTag is a Workspace Device tag.
	DestinationDeviceTag
	// DestinationResource is one Resource.
	DestinationResource
	// DestinationResourceGroup is a Resource Group.
	DestinationResourceGroup
	// DestinationImportedResource is a consumer-local Imported Resource.
	DestinationImportedResource
	// DestinationSite is a Site with the prefixes the rule grants.
	DestinationSite
	// DestinationExitPool is the Internet through an Exit Pool.
	DestinationExitPool
)

// String returns the stable audit name of the kind.
func (kind DestinationKind) String() string {
	switch kind {
	case DestinationDevice:
		return "device"
	case DestinationDeviceGroup:
		return "device_group"
	case DestinationDeviceTag:
		return "device_tag"
	case DestinationResource:
		return "resource"
	case DestinationResourceGroup:
		return "resource_group"
	case DestinationImportedResource:
		return "imported_resource"
	case DestinationSite:
		return "site"
	case DestinationExitPool:
		return "exit_pool"
	default:
		return "unknown"
	}
}

func (kind DestinationKind) isValid() bool {
	return kind > DestinationUnknown && kind <= DestinationExitPool
}

// RuleFingerprint identifies one Access Rule as written: its sources,
// destination, protocol and ports, but not what its Resources or shares
// resolved to. The release semantic hash covers those.
type RuleFingerprint struct {
	ruleID          policy.RuleID
	destinationKind DestinationKind
	destinationID   publicid.ID
	digest          [16]byte
}

// RuleFingerprintSet is the fingerprints of one release, ordered by rule ID.
// The zero value is an empty set.
type RuleFingerprintSet struct{ entries []RuleFingerprint }

// Len returns the number of rules.
func (set RuleFingerprintSet) Len() int { return len(set.entries) }

type ruleFingerprintParts struct {
	kind        DestinationKind
	destination publicid.ID
	parts       []string
}

// FingerprintRules computes the fingerprint of every Access Rule in the
// candidate. A rule compiled into several parts (one per Resource Group
// member or source Device) yields one fingerprint.
func FingerprintRules(candidate Candidate) (RuleFingerprintSet, error) {
	byRule := make(map[policy.RuleID]*ruleFingerprintParts)
	add := func(ruleID policy.RuleID, kind DestinationKind, destination publicid.ID, part string) error {
		if !ruleID.IsValid() || !kind.isValid() || !destination.IsValid() {
			return ErrInvalidRuleFingerprints
		}
		entry, found := byRule[ruleID]
		if !found {
			entry = &ruleFingerprintParts{kind: kind, destination: destination}
			byRule[ruleID] = entry
		} else if entry.kind != kind || entry.destination != destination {
			return ErrInvalidRuleFingerprints
		}
		entry.parts = append(entry.parts, part)
		return nil
	}
	type destinationKey struct{ ruleID, nodeID string }
	resources := make(map[destinationKey]publicid.ID)
	for _, destination := range candidate.ResourceDestinations() {
		key := destinationKey{destination.RuleID().String(), destination.DestinationNodeID().String()}
		resources[key] = publicid.ID(destination.Reference().ResourceID())
	}
	resourceGroups := make(map[destinationKey]publicid.ID)
	for _, destination := range candidate.ResourceGroupDestinations() {
		for _, member := range destination.Members() {
			key := destinationKey{destination.RuleID().String(), member.DestinationNodeID().String()}
			resourceGroups[key] = publicid.ID(destination.ResourceGroupID())
		}
	}
	for _, rule := range candidate.Snapshot().Rules() {
		key := destinationKey{rule.ID().String(), rule.DestinationNodeID().String()}
		traffic := ruleTrafficPart(rule.SourceNodeID().String(), rule.Protocol(), rule.DestinationPortRanges())
		var err error
		if resourceID, found := resources[key]; found {
			err = add(rule.ID(), DestinationResource, resourceID, traffic)
		} else if groupID, found := resourceGroups[key]; found {
			err = add(rule.ID(), DestinationResourceGroup, groupID, traffic)
		} else {
			err = add(rule.ID(), DestinationDevice, publicid.ID(rule.DestinationNodeID()), traffic)
		}
		if err != nil {
			return RuleFingerprintSet{}, err
		}
	}
	for _, destination := range candidate.ImportedResourceDestinations() {
		traffic := ruleTrafficPart(destination.SourceNodeID().String(), destination.Protocol(),
			destination.DestinationPortRanges())
		importedID := publicid.ID(destination.Resolution().ImportedResourceID())
		if err := add(destination.RuleID(), DestinationImportedResource, importedID, traffic); err != nil {
			return RuleFingerprintSet{}, err
		}
	}
	for _, rule := range candidate.GroupRules() {
		kind := ruleSideToken(rule.Source().Kind())
		if kind == "" {
			return RuleFingerprintSet{}, ErrInvalidRuleFingerprints
		}
		source := kind + ":" + rule.Source().ID().String()
		traffic := ruleTrafficPart(source, rule.Protocol(), rule.DestinationPortRanges())
		if err := add(rule.RuleID(), groupRuleDestinationKind(rule.Destination().Kind()),
			rule.Destination().ID(), traffic); err != nil {
			return RuleFingerprintSet{}, err
		}
	}
	for _, rule := range candidate.RouteRules() {
		kind := ruleSideToken(rule.Source().Kind())
		if kind == "" {
			return RuleFingerprintSet{}, ErrInvalidRuleFingerprints
		}
		prefixes := make([]string, 0, len(rule.Prefixes()))
		for _, prefix := range rule.Prefixes() {
			prefixes = append(prefixes, prefix.String())
		}
		source := kind + ":" + rule.Source().ID().String() + ">" + strings.Join(prefixes, ",")
		traffic := ruleTrafficPart(source, rule.Protocol(), rule.DestinationPortRanges())
		if err := add(rule.RuleID(), DestinationSite, publicid.ID(rule.SiteID()), traffic); err != nil {
			return RuleFingerprintSet{}, err
		}
	}
	for _, rule := range candidate.ExitRules() {
		kind := ruleSideToken(rule.Source().Kind())
		if kind == "" {
			return RuleFingerprintSet{}, ErrInvalidRuleFingerprints
		}
		source := kind + ":" + rule.Source().ID().String()
		traffic := ruleTrafficPart(source, rule.Protocol(), rule.DestinationPortRanges())
		if err := add(rule.RuleID(), DestinationExitPool, publicid.ID(rule.PoolID()), traffic); err != nil {
			return RuleFingerprintSet{}, err
		}
	}
	entries := make([]RuleFingerprint, 0, len(byRule))
	for ruleID, entry := range byRule {
		entries = append(entries, RuleFingerprint{
			ruleID: ruleID, destinationKind: entry.kind, destinationID: entry.destination,
			digest: ruleFingerprintDigest(entry),
		})
	}
	slices.SortFunc(entries, compareRuleFingerprints)
	return RuleFingerprintSet{entries: entries}, nil
}

// ruleSideToken names a group rule side in fingerprints. The tokens are
// fixed so that reordering SideKind never changes a digest.
func ruleSideToken(kind SideKind) string {
	switch kind {
	case SideDevice:
		return "device"
	case SideDeviceGroup:
		return "device_group"
	case SideIdentityGroup:
		return "identity_group"
	case SideDeviceTag:
		return "device_tag"
	default:
		return ""
	}
}

// ruleProtocolToken names a protocol in fingerprints, fixed for the same
// reason.
func ruleProtocolToken(protocol policy.Protocol) string {
	switch protocol {
	case policy.ProtocolTCP:
		return "tcp"
	case policy.ProtocolUDP:
		return "udp"
	case policy.ProtocolICMP:
		return "icmp"
	default:
		return ""
	}
}

func groupRuleDestinationKind(kind SideKind) DestinationKind {
	switch kind {
	case SideDevice:
		return DestinationDevice
	case SideDeviceGroup:
		return DestinationDeviceGroup
	case SideDeviceTag:
		return DestinationDeviceTag
	default:
		return DestinationUnknown
	}
}

// ruleTrafficPart is one compiled part of a rule: its source, protocol and
// sorted port ranges.
func ruleTrafficPart(source string, protocol policy.Protocol, ports []policy.PortRange) string {
	ranges := make([]string, len(ports))
	for index, portRange := range ports {
		ranges[index] = strconv.Itoa(int(portRange.First())) + "-" + strconv.Itoa(int(portRange.Last()))
	}
	slices.Sort(ranges)
	return source + "|" + ruleProtocolToken(protocol) + "|" + strings.Join(ranges, ",")
}

func ruleFingerprintDigest(entry *ruleFingerprintParts) [16]byte {
	parts := slices.Clone(entry.parts)
	slices.Sort(parts)
	parts = slices.Compact(parts)
	destination := entry.destination.Bytes()
	hash := sha256.New()
	hash.Write([]byte("meshtransit policy rule fingerprint v1\x00"))
	hash.Write([]byte{byte(entry.kind)})
	hash.Write(destination[:])
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	var digest [16]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func compareRuleFingerprints(left, right RuleFingerprint) int {
	leftID, rightID := publicid.ID(left.ruleID).Bytes(), publicid.ID(right.ruleID).Bytes()
	return bytes.Compare(leftID[:], rightID[:])
}

// MarshalBinary encodes the set: a format byte, a big-endian rule count and
// one RuleFingerprintSize entry per rule in rule ID order.
func (set RuleFingerprintSet) MarshalBinary() []byte {
	encoded := make([]byte, ruleFingerprintHeaderSize, ruleFingerprintHeaderSize+len(set.entries)*RuleFingerprintSize)
	encoded[0] = ruleFingerprintFormat
	binary.BigEndian.PutUint32(encoded[1:], uint32(len(set.entries))) //nolint:gosec // bounded by policy.MaximumRules
	for _, entry := range set.entries {
		ruleID, destinationID := publicid.ID(entry.ruleID).Bytes(), entry.destinationID.Bytes()
		encoded = append(encoded, ruleID[:]...)
		encoded = append(encoded, byte(entry.destinationKind))
		encoded = append(encoded, destinationID[:]...)
		encoded = append(encoded, entry.digest[:]...)
	}
	return encoded
}

// ParseRuleFingerprintSet decodes MarshalBinary output and rejects anything
// else: another format, a wrong length, unordered or invalid entries.
func ParseRuleFingerprintSet(encoded []byte) (RuleFingerprintSet, error) {
	if len(encoded) < ruleFingerprintHeaderSize || encoded[0] != ruleFingerprintFormat {
		return RuleFingerprintSet{}, ErrInvalidRuleFingerprints
	}
	count := binary.BigEndian.Uint32(encoded[1:ruleFingerprintHeaderSize])
	if count > policy.MaximumRules ||
		len(encoded) != ruleFingerprintHeaderSize+int(count)*RuleFingerprintSize {
		return RuleFingerprintSet{}, ErrInvalidRuleFingerprints
	}
	entries := make([]RuleFingerprint, count)
	for index := range entries {
		offset := ruleFingerprintHeaderSize + index*RuleFingerprintSize
		ruleID, ruleErr := publicid.FromBytes([16]byte(encoded[offset : offset+16]))
		kind := DestinationKind(encoded[offset+16])
		destinationID, destinationErr := publicid.FromBytes([16]byte(encoded[offset+17 : offset+33]))
		if ruleErr != nil || destinationErr != nil || !kind.isValid() {
			return RuleFingerprintSet{}, ErrInvalidRuleFingerprints
		}
		entries[index] = RuleFingerprint{
			ruleID: policy.RuleID(ruleID), destinationKind: kind, destinationID: destinationID,
			digest: [16]byte(encoded[offset+33 : offset+RuleFingerprintSize]),
		}
		if index > 0 && compareRuleFingerprints(entries[index-1], entries[index]) >= 0 {
			return RuleFingerprintSet{}, ErrInvalidRuleFingerprints
		}
	}
	return RuleFingerprintSet{entries: entries}, nil
}

// RuleChangeKind says how one Access Rule changed.
type RuleChangeKind uint8

const (
	// RuleChangeUnknown is invalid.
	RuleChangeUnknown RuleChangeKind = iota
	// RuleChangeRemoved is a rule only the previous release had.
	RuleChangeRemoved
	// RuleChangeChanged is a rule both releases have, written differently.
	RuleChangeChanged
	// RuleChangeAdded is a rule only the new release has.
	RuleChangeAdded
)

// String returns the stable audit name of the change.
func (kind RuleChangeKind) String() string {
	switch kind {
	case RuleChangeRemoved:
		return "removed"
	case RuleChangeChanged:
		return "changed"
	case RuleChangeAdded:
		return "added"
	default:
		return "unknown"
	}
}

// RuleChange names one changed Access Rule and its destination: the new one
// for an added or changed rule, the old one for a removed rule.
type RuleChange struct {
	kind            RuleChangeKind
	ruleID          policy.RuleID
	destinationKind DestinationKind
	destinationID   publicid.ID
}

// Kind returns how the rule changed.
func (change RuleChange) Kind() RuleChangeKind { return change.kind }

// RuleID returns the Access Rule.
func (change RuleChange) RuleID() policy.RuleID { return change.ruleID }

// DestinationKind returns what the rule's destination selects.
func (change RuleChange) DestinationKind() DestinationKind { return change.destinationKind }

// DestinationID returns the destination's public ID.
func (change RuleChange) DestinationID() publicid.ID { return change.destinationID }

// RuleBaseline says what a publication's rules were compared with.
type RuleBaseline uint8

const (
	// RuleBaselineUnknown is invalid.
	RuleBaselineUnknown RuleBaseline = iota
	// RuleBaselineNone means the Network had no release: every rule is new.
	RuleBaselineNone
	// RuleBaselinePreviousRelease means the replaced release's fingerprints.
	RuleBaselinePreviousRelease
	// RuleBaselineUnavailable means the replaced release kept no
	// fingerprints (published before they existed, or by an older Core).
	RuleBaselineUnavailable
	// RuleBaselineUnreadable means the replaced release's fingerprints did
	// not decode, which only a change to the stored row can cause.
	// Publication goes ahead, since it may be revoking access.
	RuleBaselineUnreadable
)

// String returns the stable audit name of the baseline.
func (baseline RuleBaseline) String() string {
	switch baseline {
	case RuleBaselineNone:
		return "none"
	case RuleBaselinePreviousRelease:
		return "previous_release"
	case RuleBaselineUnavailable:
		return "unavailable"
	case RuleBaselineUnreadable:
		return "unreadable"
	default:
		return "unknown"
	}
}

// RuleChangeSummary is what one publication changed in the Access Rules.
type RuleChangeSummary struct {
	baseline                           RuleBaseline
	added, removed, changed, unchanged int
	rules                              []RuleChange
	truncated                          bool
}

// Baseline says what the rules were compared with.
func (summary RuleChangeSummary) Baseline() RuleBaseline { return summary.baseline }

// BaselineKnown reports whether the previous rules were known (no release,
// or the replaced release's fingerprints). Otherwise the summary counts
// nothing.
func (summary RuleChangeSummary) BaselineKnown() bool {
	return summary.baseline == RuleBaselineNone || summary.baseline == RuleBaselinePreviousRelease
}

// Added returns the number of new rules.
func (summary RuleChangeSummary) Added() int { return summary.added }

// Removed returns the number of rules no longer published.
func (summary RuleChangeSummary) Removed() int { return summary.removed }

// Changed returns the number of rules kept with another source, destination,
// protocol or ports.
func (summary RuleChangeSummary) Changed() int { return summary.changed }

// Unchanged returns the number of rules published again as they were.
func (summary RuleChangeSummary) Unchanged() int { return summary.unchanged }

// Rules returns at most MaximumListedRuleChanges changed rules: removed,
// then changed, then added, each in rule ID order.
func (summary RuleChangeSummary) Rules() []RuleChange { return slices.Clone(summary.rules) }

// Truncated reports whether more rules changed than Rules lists.
func (summary RuleChangeSummary) Truncated() bool { return summary.truncated }

// SummarizeRuleChanges compares previous with the new fingerprints. With
// RuleBaselineNone previous must be empty; with an unavailable or unreadable
// baseline (or an invalid one) nothing is counted.
func SummarizeRuleChanges(
	previous RuleFingerprintSet,
	baseline RuleBaseline,
	next RuleFingerprintSet,
) RuleChangeSummary {
	summary := RuleChangeSummary{baseline: baseline}
	switch baseline {
	case RuleBaselineNone:
		previous = RuleFingerprintSet{}
	case RuleBaselinePreviousRelease:
	case RuleBaselineUnavailable, RuleBaselineUnreadable:
		return summary
	default:
		return RuleChangeSummary{baseline: RuleBaselineUnknown}
	}
	var lists [3][]RuleChange
	note := func(kind RuleChangeKind, entry RuleFingerprint) {
		lists[kind-RuleChangeRemoved] = append(lists[kind-RuleChangeRemoved], RuleChange{
			kind: kind, ruleID: entry.ruleID, destinationKind: entry.destinationKind,
			destinationID: entry.destinationID,
		})
	}
	old, current := previous.entries, next.entries
	for len(old) > 0 || len(current) > 0 {
		var order int
		switch {
		case len(old) == 0:
			order = 1
		case len(current) == 0:
			order = -1
		default:
			order = compareRuleFingerprints(old[0], current[0])
		}
		switch {
		case order < 0:
			summary.removed++
			note(RuleChangeRemoved, old[0])
			old = old[1:]
		case order > 0:
			summary.added++
			note(RuleChangeAdded, current[0])
			current = current[1:]
		default:
			if old[0].destinationKind == current[0].destinationKind &&
				old[0].destinationID == current[0].destinationID && old[0].digest == current[0].digest {
				summary.unchanged++
			} else {
				summary.changed++
				note(RuleChangeChanged, current[0])
			}
			old, current = old[1:], current[1:]
		}
	}
	// Share the listed rules out between the three kinds, so a large
	// addition cannot hide a removal.
	var quota [3]int
	listed := 0
	for listed < MaximumListedRuleChanges {
		progressed := false
		for index := range lists {
			if quota[index] < len(lists[index]) && listed < MaximumListedRuleChanges {
				quota[index]++
				listed++
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	summary.rules = make([]RuleChange, 0, listed)
	for index := range lists {
		summary.rules = append(summary.rules, lists[index][:quota[index]]...)
	}
	summary.truncated = listed < summary.added+summary.removed+summary.changed
	return summary
}
