package policy

import (
	"errors"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const (
	// MaximumRules bounds one immutable active Network policy artifact.
	MaximumRules = 10_000
)

var (
	// ErrInvalidSnapshot reports incomplete or inconsistent compiled policy state.
	ErrInvalidSnapshot = errors.New("policy: invalid snapshot")
	// ErrRuleLimit reports an active rule set above the evaluator safety ceiling.
	ErrRuleLimit = errors.New("policy: rule limit exceeded")
)

// SnapshotParams contains exact active-release input for one Network revision.
type SnapshotParams struct {
	Scope    network.Scope
	Revision int64
	Rules    []Rule
}

type nodePair struct {
	source      node.ID
	destination node.ID
}

// Snapshot is an immutable, Network-scoped, active packet-policy artifact.
// Its zero value is invalid; an explicitly constructed empty rule set denies all.
type Snapshot struct {
	scope       network.Scope
	revision    int64
	rules       []Rule
	rulesByPair map[nodePair][]int
	// valid is set only by NewSnapshot after full validation; the snapshot
	// is immutable, so IsValid need not validate every rule again (it is
	// called once per peer candidate when a map is built).
	valid bool
}

// NewSnapshot validates, copies, and indexes one active policy artifact.
func NewSnapshot(params SnapshotParams) (Snapshot, error) {
	if len(params.Rules) > MaximumRules {
		return Snapshot{}, errors.Join(ErrInvalidSnapshot, ErrRuleLimit)
	}
	rules := cloneRules(params.Rules)
	slices.SortFunc(rules, compareRules)
	if !validSnapshotRules(params.Scope, params.Revision, rules) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	rulesByPair := make(map[nodePair][]int, min(len(rules), 64))
	for index, rule := range rules {
		pair := nodePair{source: rule.sourceNodeID, destination: rule.destinationNodeID}
		rulesByPair[pair] = append(rulesByPair[pair], index)
	}
	return Snapshot{
		scope:       params.Scope,
		revision:    params.Revision,
		rules:       rules,
		rulesByPair: rulesByPair,
		valid:       true,
	}, nil
}

// Scope returns the exact Workspace-qualified Network scope.
func (snapshot Snapshot) Scope() network.Scope { return snapshot.scope }

// Revision returns the active authoritative policy revision.
func (snapshot Snapshot) Revision() int64 { return snapshot.revision }

// Rules returns a caller-owned deterministic copy of active compiled rules.
func (snapshot Snapshot) Rules() []Rule { return cloneRules(snapshot.rules) }

// IsValid reports whether the snapshot is exact-scoped, bounded, and canonical.
func (snapshot Snapshot) IsValid() bool {
	return snapshot.valid && snapshot.rulesByPair != nil
}

// PeersOf returns, sorted and without duplicates, every Node an explicit
// rule pairs with self in either direction: exactly the Nodes for which
// AllowsPeer(self, peer) holds. It costs one pass over the rules, which a
// Node-reduced policy keeps to self's own.
func (snapshot Snapshot) PeersOf(self node.ID) []node.ID {
	if !snapshot.IsValid() || !self.IsValid() {
		return []node.ID{}
	}
	seen := make(map[node.ID]struct{}, len(snapshot.rules))
	peers := make([]node.ID, 0, len(snapshot.rules))
	for _, rule := range snapshot.rules {
		peer := rule.destinationNodeID
		switch {
		case rule.sourceNodeID == self && rule.destinationNodeID != self:
		case rule.destinationNodeID == self && rule.sourceNodeID != self:
			peer = rule.sourceNodeID
		default:
			continue
		}
		if _, exists := seen[peer]; !exists {
			seen[peer] = struct{}{}
			peers = append(peers, peer)
		}
	}
	slices.SortFunc(peers, func(first, second node.ID) int { return strings.Compare(first.String(), second.String()) })
	return peers
}

// AllowsPeer reports whether an explicit rule in either direction requires the
// two Nodes to share peer identity. It does not itself authorize any packet.
func (snapshot Snapshot) AllowsPeer(first, second node.ID) bool {
	if !snapshot.IsValid() || !first.IsValid() || !second.IsValid() || first == second {
		return false
	}
	return len(snapshot.rulesFor(first, second)) > 0 || len(snapshot.rulesFor(second, first)) > 0
}

// Equal reports whether two snapshots contain the same immutable policy facts.
func (snapshot Snapshot) Equal(other Snapshot) bool {
	return snapshot.IsValid() && other.IsValid() && snapshot.scope == other.scope &&
		snapshot.revision == other.revision && slices.EqualFunc(snapshot.rules, other.rules, equalRules)
}

func (snapshot Snapshot) rulesFor(source, destination node.ID) []int {
	return snapshot.rulesByPair[nodePair{source: source, destination: destination}]
}

func cloneRules(rules []Rule) []Rule {
	cloned := make([]Rule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule.clone()
	}
	return cloned
}

func validSnapshotRules(scope network.Scope, revision int64, rules []Rule) bool {
	if !scope.IsValid() || revision <= 0 || rules == nil || len(rules) > MaximumRules {
		return false
	}
	for index, rule := range rules {
		if !rule.IsValid() || rule.scope != scope || index > 0 && compareRules(rules[index-1], rule) >= 0 {
			return false
		}
	}
	return true
}
