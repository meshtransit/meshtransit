package mapsession

import (
	"errors"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

var (
	// ErrInvalidConnectivity reports transient state without an exact Node fence.
	ErrInvalidConnectivity = errors.New("map session: invalid connectivity")
	// ErrInvalidConnectivityChange reports a malformed Redis wakeup hint.
	ErrInvalidConnectivityChange = errors.New("map session: invalid connectivity change")
)

// ConnectivityChangeKind distinguishes endpoint content from presence state so
// a stream can ignore its own lease churn without missing discovery updates.
type ConnectivityChangeKind uint8

const (
	// ConnectivityChangeUnknown is the invalid zero value.
	ConnectivityChangeUnknown ConnectivityChangeKind = iota
	// ConnectivityChangeEndpoints reports discovery-key or endpoint-set change.
	ConnectivityChangeEndpoints
	// ConnectivityChangePresence reports exact-generation online-state change.
	ConnectivityChangePresence
)

// IsValid reports whether this change kind is supported.
func (kind ConnectivityChangeKind) IsValid() bool {
	return kind == ConnectivityChangeEndpoints || kind == ConnectivityChangePresence
}

// ConnectivityKey identifies one exact Node session generation. It carries no
// membership or policy authority.
type ConnectivityKey struct {
	nodeID     node.ID
	generation int64
}

// NewConnectivityKey validates one transient-state lookup key.
func NewConnectivityKey(nodeID node.ID, generation int64) (ConnectivityKey, error) {
	key := ConnectivityKey{nodeID: nodeID, generation: generation}
	if !key.IsValid() {
		return ConnectivityKey{}, ErrInvalidConnectivity
	}
	return key, nil
}

// NodeID returns the globally stable Node identity.
func (key ConnectivityKey) NodeID() node.ID { return key.nodeID }

// Generation returns the exact durable session-generation fence.
func (key ConnectivityKey) Generation() int64 { return key.generation }

// IsValid reports whether the lookup key is complete.
func (key ConnectivityKey) IsValid() bool {
	return key.nodeID.IsValid() && key.generation > 0
}

// ConnectivityParams contains one exact-generation, non-authoritative Redis
// projection. EndpointSetPresent distinguishes a withdrawal from no report.
type ConnectivityParams struct {
	Key                   ConnectivityKey
	EndpointSet           node.EndpointSet
	EndpointSetPresent    bool
	PreferredRelay        int
	PreferredRelayPresent bool
	Online                bool
}

// Connectivity is immutable transient routing state. It never grants peer
// visibility; the enclosing authoritative snapshot supplies that decision.
type Connectivity struct {
	key                   ConnectivityKey
	endpointSet           node.EndpointSet
	endpointSetPresent    bool
	preferredRelay        int
	preferredRelayPresent bool
	online                bool
}

// NewConnectivity validates one exact-generation transient projection.
func NewConnectivity(params ConnectivityParams) (Connectivity, error) {
	if !params.Key.IsValid() || params.EndpointSetPresent != params.EndpointSet.IsValid() ||
		params.PreferredRelay < 0 || params.PreferredRelay > node.MaximumRelayRegionID ||
		(!params.PreferredRelayPresent && params.PreferredRelay != 0) {
		return Connectivity{}, ErrInvalidConnectivity
	}
	return Connectivity{
		key:                   params.Key,
		endpointSet:           params.EndpointSet,
		endpointSetPresent:    params.EndpointSetPresent,
		preferredRelay:        params.PreferredRelay,
		preferredRelayPresent: params.PreferredRelayPresent,
		online:                params.Online,
	}, nil
}

// PreferredRelay returns the reported home relay when present. A present zero
// is an explicit withdrawal, not an omitted observation.
func (connectivity Connectivity) PreferredRelay() (int, bool) {
	return connectivity.preferredRelay, connectivity.preferredRelayPresent
}

// Key returns the exact Node generation represented by this observation.
func (connectivity Connectivity) Key() ConnectivityKey { return connectivity.key }

// EndpointSet returns a valid report when present. Absence is a normal cache miss.
func (connectivity Connectivity) EndpointSet() (node.EndpointSet, bool) {
	return connectivity.endpointSet, connectivity.endpointSetPresent
}

// Online reports whether an exact-generation presence lease currently exists.
func (connectivity Connectivity) Online() bool { return connectivity.online }

// IsValid reports whether the projection is complete and generation-fenced.
func (connectivity Connectivity) IsValid() bool {
	return connectivity.key.IsValid() &&
		connectivity.endpointSetPresent == connectivity.endpointSet.IsValid() &&
		connectivity.preferredRelay >= 0 &&
		connectivity.preferredRelay <= node.MaximumRelayRegionID &&
		(connectivity.preferredRelayPresent || connectivity.preferredRelay == 0)
}

func (connectivity Connectivity) equal(other Connectivity) bool {
	if connectivity.key != other.key || connectivity.online != other.online ||
		connectivity.endpointSetPresent != other.endpointSetPresent ||
		connectivity.preferredRelay != other.preferredRelay ||
		connectivity.preferredRelayPresent != other.preferredRelayPresent {
		return false
	}
	return !connectivity.endpointSetPresent || connectivity.endpointSet.Equal(other.endpointSet)
}

// ConnectivityChanged is a best-effort, non-authoritative refresh hint scoped
// to one Network and exact Node generation.
type ConnectivityChanged struct {
	networkID network.ID
	key       ConnectivityKey
	kind      ConnectivityChangeKind
}

// NewConnectivityChanged validates one transient wakeup hint.
func NewConnectivityChanged(
	networkID network.ID,
	nodeID node.ID,
	generation int64,
	kind ConnectivityChangeKind,
) (ConnectivityChanged, error) {
	key, err := NewConnectivityKey(nodeID, generation)
	if err != nil || !networkID.IsValid() || !kind.IsValid() {
		return ConnectivityChanged{}, ErrInvalidConnectivityChange
	}
	return ConnectivityChanged{networkID: networkID, key: key, kind: kind}, nil
}

// NetworkID returns the routing scope for local fan-out.
func (change ConnectivityChanged) NetworkID() network.ID { return change.networkID }

// Key returns the exact Node generation whose transient state changed.
func (change ConnectivityChanged) Key() ConnectivityKey { return change.key }

// Kind returns which non-authoritative connectivity component changed.
func (change ConnectivityChanged) Kind() ConnectivityChangeKind { return change.kind }

// IsValid reports whether the wakeup can be safely routed.
func (change ConnectivityChanged) IsValid() bool {
	return change.networkID.IsValid() && change.key.IsValid() && change.kind.IsValid()
}

func canonicalConnectivity(values []Connectivity) []Connectivity {
	canonical := slices.Clone(values)
	slices.SortFunc(canonical, func(left, right Connectivity) int {
		return strings.Compare(left.key.nodeID.String(), right.key.nodeID.String())
	})
	return canonical
}
