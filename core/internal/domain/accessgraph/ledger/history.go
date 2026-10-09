package ledger

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// MaximumPageSize bounds each authenticated history page.
const MaximumPageSize = 500

var (
	// ErrInvalidRequest reports invalid input before any read.
	ErrInvalidRequest = errors.New("access graph history: invalid request")
	// ErrInvalidResult conceals malformed storage evidence.
	ErrInvalidResult = errors.New("access graph history: invalid result")
	// ErrForbidden conceals missing or revoked exact-scope authority.
	ErrForbidden = errors.New("access graph history: forbidden")
	// ErrUnavailable reports a failed durable dependency.
	ErrUnavailable = errors.New("access graph history: unavailable")
)

// EdgeKey identifies one edge over time: the same source, destination,
// rule, provenance, protocol, ports and expiry.
type EdgeKey [32]byte

// ParseEdgeKey accepts the lowercase hex form returned by String.
func ParseEdgeKey(value string) (EdgeKey, error) {
	var key EdgeKey
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(key) || hex.EncodeToString(decoded) != value {
		return EdgeKey{}, ErrInvalidRequest
	}
	copy(key[:], decoded)
	return key, nil
}

// String returns the lowercase hex form.
func (key EdgeKey) String() string { return hex.EncodeToString(key[:]) }

// IsZero reports the absent key.
func (key EdgeKey) IsZero() bool { return key == EdgeKey{} }

// Selector kinds of an edge's destination.
const (
	SelectorDevice           = "device"
	SelectorResource         = "resource"
	SelectorResourceGroup    = "resource_group"
	SelectorImportedResource = "imported_resource"
)

// Edge is one source reaching one destination through one rule, valid from
// ValidFrom until ValidTo (zero while it still holds). Optional identifiers
// are zero when absent; ExpiresAt is zero when neither end expires.
type Edge struct {
	Key                     EdgeKey
	AccessRuleID            publicid.ID
	SelectorKind            string
	SourceDeviceID          node.ID
	SourceHostname          string
	DestinationDeviceID     node.ID
	DestinationHostname     string
	ImportedResourceID      publicid.ID
	TrustContractID         publicid.ID
	ResourceID              publicid.ID
	ResourceGroupID         publicid.ID
	SourceSelectorKind      string
	SourceSelectorID        publicid.ID
	DestinationSelectorKind string
	DestinationSelectorID   publicid.ID
	Protocol                policy.Protocol
	Ports                   []policy.PortRange
	ValidFromRevision       int64
	ValidFrom               time.Time
	ValidToRevision         int64
	ValidTo                 time.Time
	ExpiresAt               time.Time
}

// Snapshot is the sealed record of the edge set in effect at a revision.
type Snapshot struct {
	ID              publicid.ID
	NetworkRevision int64
	EffectiveAt     time.Time
	RecordedAt      time.Time
	EdgeCount       int
	Digest          string
}

// Query selects edges at one instant. Zero device filters match any Device;
// a zero protocol matches any protocol.
type Query struct {
	At          time.Time
	Device      node.ID
	Source      node.ID
	Destination node.ID
	Protocol    policy.Protocol
	After       EdgeKey
	Limit       int
}

// Result is the durable side of one page; Edges may hold one extra row that
// tells the service another page follows.
type Result struct {
	Scope           network.Scope
	At              time.Time
	RecordedSince   time.Time
	NetworkRevision int64
	Snapshot        *Snapshot
	Edges           []Edge
}

// Reader authorizes and reads one page under policy.read and device.read.
type Reader interface {
	ReadHistory(context.Context, accountsession.Session, network.Scope, Query, time.Time) (Result, error)
}

// Clock provides the current authority-evaluation instant.
type Clock interface{ Now() time.Time }

// Page is one ordered page of edges in effect at At.
type Page struct {
	Scope network.Scope
	At    time.Time
	// RecordedSince is when the ledger began for this Network; zero when it
	// has not recorded yet. Earlier instants have no answer.
	RecordedSince   time.Time
	NetworkRevision int64
	Snapshot        *Snapshot
	Edges           []Edge
	// Next is the key to continue after, or zero on the last page.
	Next EdgeKey
}

// Service reads the ledger at a past or present instant.
type Service struct {
	reader Reader
	clock  Clock
}

// NewService constructs a history reader through explicit dependencies.
func NewService(reader Reader, clock Clock) (*Service, error) {
	if reader == nil || clock == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{reader: reader, clock: clock}, nil
}

// Read returns one page. A zero At reads the present.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	query Query) (Page, error) {
	if service == nil || ctx == nil || !session.IsValid() || !scope.IsValid() || !validQuery(query) {
		return Page{}, ErrInvalidRequest
	}
	// PostgreSQL keeps microseconds; the instant must survive the round trip.
	now := service.clock.Now().UTC().Truncate(time.Microsecond)
	if query.At.IsZero() {
		query.At = now
	}
	query.At = query.At.UTC().Truncate(time.Microsecond)
	if query.At.After(now) {
		return Page{}, ErrInvalidRequest
	}
	limit := query.Limit
	query.Limit = limit + 1
	result, err := service.reader.ReadHistory(ctx, session, scope, query, now)
	if err != nil {
		return Page{}, err
	}
	if !validResult(result, scope, query) {
		return Page{}, ErrInvalidResult
	}
	page := Page{Scope: scope, At: result.At, RecordedSince: result.RecordedSince,
		NetworkRevision: result.NetworkRevision, Snapshot: result.Snapshot, Edges: result.Edges}
	if len(page.Edges) > limit {
		page.Edges = page.Edges[:limit]
		page.Next = page.Edges[limit-1].Key
	}
	return page, nil
}

func validQuery(query Query) bool {
	optional := func(id node.ID) bool { return id == node.ID{} || id.IsValid() }
	protocol := query.Protocol == policy.ProtocolUnknown || query.Protocol.IsValid()
	return query.Limit >= 1 && query.Limit <= MaximumPageSize && optional(query.Device) &&
		optional(query.Source) && optional(query.Destination) && protocol
}

func validResult(result Result, scope network.Scope, query Query) bool {
	if result.Scope != scope || !result.At.Equal(query.At) || result.NetworkRevision < 0 ||
		len(result.Edges) > query.Limit {
		return false
	}
	if result.RecordedSince.IsZero() && len(result.Edges) != 0 {
		return false
	}
	if snapshot := result.Snapshot; snapshot != nil && (!snapshot.ID.IsValid() || snapshot.NetworkRevision < 1 ||
		snapshot.EdgeCount < 0 || len(snapshot.Digest) != 64 || snapshot.EffectiveAt.After(query.At)) {
		return false
	}
	previous := query.After
	for _, edge := range result.Edges {
		if !validEdge(edge, query) || (!previous.IsZero() && edge.Key.String() <= previous.String()) {
			return false
		}
		previous = edge.Key
	}
	return true
}

func validEdge(edge Edge, query Query) bool {
	local := edge.SelectorKind == SelectorDevice || edge.SelectorKind == SelectorResource ||
		edge.SelectorKind == SelectorResourceGroup
	imported := edge.SelectorKind == SelectorImportedResource
	shape := local && edge.DestinationDeviceID.IsValid() && edge.ImportedResourceID == (publicid.ID{}) ||
		imported && edge.DestinationDeviceID == (node.ID{}) && edge.ImportedResourceID.IsValid() &&
			edge.TrustContractID.IsValid()
	open := edge.ValidToRevision == 0 && edge.ValidTo.IsZero()
	closed := edge.ValidToRevision > edge.ValidFromRevision && edge.ValidTo.After(query.At)
	inEffect := !edge.ValidFrom.After(query.At) && (open || closed) &&
		(edge.ExpiresAt.IsZero() || edge.ExpiresAt.After(query.At))
	filtered := (query.Device == node.ID{} || edge.SourceDeviceID == query.Device ||
		edge.DestinationDeviceID == query.Device) &&
		(query.Source == node.ID{} || edge.SourceDeviceID == query.Source) &&
		(query.Destination == node.ID{} || edge.DestinationDeviceID == query.Destination) &&
		(query.Protocol == policy.ProtocolUnknown || edge.Protocol == query.Protocol)
	return !edge.Key.IsZero() && edge.AccessRuleID.IsValid() && edge.SourceDeviceID.IsValid() && shape &&
		edge.Protocol.IsValid() &&
		edge.ValidFromRevision > 0 && inEffect && filtered
}
