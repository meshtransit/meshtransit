package accessgraph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

const (
	// DefaultGraphPageSize is the number of compiled edges in one page when
	// the caller does not choose.
	DefaultGraphPageSize = 100
	// MaximumGraphPageSize bounds the topology disclosed by one page.
	MaximumGraphPageSize = 500
	// maximumGraphCursorBytes bounds the opaque continuation token.
	maximumGraphCursorBytes = 256
	graphCursorVersion      = 2
	// legacyGraphCursorVersion tokens predate group edges; they read as stale.
	legacyGraphCursorVersion = 1
	// MaximumGroupEdges bounds the group rule pairs an unfiltered listing
	// expands; beyond it the caller narrows the listing to one Device.
	MaximumGroupEdges = 100000
)

// ErrStaleGraphCursor reports a continuation token issued for another active
// policy revision or group revision. The caller must restart from the first
// page.
var ErrStaleGraphCursor = errors.New("access graph: stale graph cursor")

// ErrGraphTooLarge reports an unfiltered listing whose group rules expand to
// more than MaximumGroupEdges Device pairs; the caller filters to a Device.
var ErrGraphTooLarge = errors.New("access graph: too many group edges to list")

// GraphCursor continues one graph listing inside the policy and group
// revisions that issued it: group rule edges follow membership and tags,
// which change without a new release. Edges are ordered by projection
// identity.
type GraphCursor struct {
	policyRevision  int64
	groupRevision   int64
	afterProjection publication.ProjectionID
	hasContinuation bool
	legacy          bool
}

// PolicyRevision returns the active policy revision the cursor belongs to.
func (cursor GraphCursor) PolicyRevision() int64 { return cursor.policyRevision }

// AfterProjection returns the last projection already returned.
func (cursor GraphCursor) AfterProjection() publication.ProjectionID {
	return cursor.afterProjection
}

// IsZero reports whether the cursor starts from the first page.
func (cursor GraphCursor) IsZero() bool { return !cursor.hasContinuation }

// GroupRevision returns the group revision the cursor belongs to.
func (cursor GraphCursor) GroupRevision() int64 { return cursor.groupRevision }

type graphCursorWire struct {
	Version         int    `json:"v"`
	PolicyRevision  int64  `json:"r"`
	GroupRevision   *int64 `json:"g,omitempty"`
	AfterProjection string `json:"p"`
}

// String returns the opaque URL-safe token, or "" for the first page.
func (cursor GraphCursor) String() string {
	if !cursor.hasContinuation {
		return ""
	}
	groupRevision := cursor.groupRevision
	encoded, err := json.Marshal(graphCursorWire{
		Version: graphCursorVersion, PolicyRevision: cursor.policyRevision,
		GroupRevision: &groupRevision, AfterProjection: cursor.afterProjection.String(),
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// ParseGraphCursor strictly decodes one continuation token. The empty string
// is the first page.
func ParseGraphCursor(value string) (GraphCursor, error) {
	if value == "" {
		return GraphCursor{}, nil
	}
	if len(value) > maximumGraphCursorBytes {
		return GraphCursor{}, ErrInvalidQuery
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		return GraphCursor{}, ErrInvalidQuery
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var wire graphCursorWire
	if err := decoder.Decode(&wire); err != nil || decoder.More() {
		return GraphCursor{}, ErrInvalidQuery
	}
	projection, err := publication.ParseProjectionID(wire.AfterProjection)
	if err != nil || wire.PolicyRevision < 1 {
		return GraphCursor{}, ErrInvalidQuery
	}
	cursor := GraphCursor{
		policyRevision: wire.PolicyRevision, afterProjection: projection, hasContinuation: true,
	}
	switch {
	case wire.Version == legacyGraphCursorVersion && wire.GroupRevision == nil:
		cursor.legacy = true
	case wire.Version == graphCursorVersion && wire.GroupRevision != nil && *wire.GroupRevision >= 0:
		cursor.groupRevision = *wire.GroupRevision
	default:
		return GraphCursor{}, ErrInvalidQuery
	}
	return cursor, nil
}

// GraphQueryParams selects one bounded page of the effective access graph.
type GraphQueryParams struct {
	Scope network.Scope
	// DeviceID, when set, keeps only edges that start or end at this Device.
	DeviceID node.ID
	// Protocol, when known, keeps only edges for this protocol.
	Protocol policy.Protocol
	// PageSize is 1..MaximumGraphPageSize; zero means DefaultGraphPageSize.
	PageSize int
	Cursor   GraphCursor
}

// GraphQuery is one validated graph page request.
type GraphQuery struct {
	scope    network.Scope
	deviceID node.ID
	protocol policy.Protocol
	pageSize int
	cursor   GraphCursor
}

// NewGraphQuery validates one graph page request.
func NewGraphQuery(params GraphQueryParams) (GraphQuery, error) {
	query := GraphQuery{
		scope: params.Scope, deviceID: params.DeviceID, protocol: params.Protocol,
		pageSize: params.PageSize, cursor: params.Cursor,
	}
	if query.pageSize == 0 {
		query.pageSize = DefaultGraphPageSize
	}
	if !query.IsValid() {
		return GraphQuery{}, ErrInvalidQuery
	}
	return query, nil
}

// Scope returns the exact Workspace-qualified Network scope.
func (query GraphQuery) Scope() network.Scope { return query.scope }

// DeviceID returns the Device filter and false when every Device is listed.
func (query GraphQuery) DeviceID() (node.ID, bool) {
	return query.deviceID, query.deviceID.IsValid()
}

// Protocol returns the protocol filter and false when every protocol is listed.
func (query GraphQuery) Protocol() (policy.Protocol, bool) {
	return query.protocol, query.protocol != policy.ProtocolUnknown
}

// PageSize returns the maximum number of edges in the page.
func (query GraphQuery) PageSize() int { return query.pageSize }

// Cursor returns the continuation position.
func (query GraphQuery) Cursor() GraphCursor { return query.cursor }

// IsValid reports whether the request is scoped and bounded.
func (query GraphQuery) IsValid() bool {
	if !query.scope.IsValid() || query.pageSize < 1 || query.pageSize > MaximumGraphPageSize {
		return false
	}
	if query.protocol != policy.ProtocolUnknown && !query.protocol.IsValid() {
		return false
	}
	return query.cursor.IsZero() ||
		(query.cursor.policyRevision > 0 && query.cursor.afterProjection.IsValid())
}

// GraphNodeKind identifies what a graph node stands for.
type GraphNodeKind uint8

const (
	// GraphNodeKindUnknown is the invalid zero value.
	GraphNodeKindUnknown GraphNodeKind = iota
	// GraphNodeKindDevice is a Device in the Network.
	GraphNodeKindDevice
	// GraphNodeKindResource is a Resource in the Network.
	GraphNodeKindResource
	// GraphNodeKindImportedResource is a Device shared into the Network.
	GraphNodeKindImportedResource
)

// String returns the stable wire spelling.
func (kind GraphNodeKind) String() string {
	switch kind {
	case GraphNodeKindDevice:
		return "device"
	case GraphNodeKindResource:
		return "resource"
	case GraphNodeKindImportedResource:
		return "imported_resource"
	default:
		return ""
	}
}

// GraphNodeParams describes one participant referenced by a page.
type GraphNodeParams struct {
	Kind               GraphNodeKind
	DeviceID           node.ID
	ResourceID         resource.ID
	ImportedResourceID sharing.ImportedResourceID
	Participant        Participant
	// Share is required exactly for an imported Resource.
	Share *ShareContext
}

// GraphNode is one validated participant of the graph.
type GraphNode struct {
	kind               GraphNodeKind
	deviceID           node.ID
	resourceID         resource.ID
	importedResourceID sharing.ImportedResourceID
	participant        Participant
	share              ShareContext
	hasShare           bool
}

// NewGraphNode validates one participant. A graph names only existing
// participants, so a missing participant is rejected.
func NewGraphNode(params GraphNodeParams) (GraphNode, error) {
	graphNode := GraphNode{
		kind: params.Kind, deviceID: params.DeviceID, resourceID: params.ResourceID,
		importedResourceID: params.ImportedResourceID, participant: params.Participant,
	}
	if params.Share != nil {
		graphNode.share, graphNode.hasShare = *params.Share, true
	}
	if !graphNode.IsValid() {
		return GraphNode{}, ErrInvalidSnapshot
	}
	return graphNode, nil
}

// Kind returns what the node stands for.
func (graphNode GraphNode) Kind() GraphNodeKind { return graphNode.kind }

// DeviceID returns the Device identity of a Device node.
func (graphNode GraphNode) DeviceID() node.ID { return graphNode.deviceID }

// ResourceID returns the Resource identity of a Resource node.
func (graphNode GraphNode) ResourceID() resource.ID { return graphNode.resourceID }

// ImportedResourceID returns the identity of a shared-in Device node.
func (graphNode GraphNode) ImportedResourceID() sharing.ImportedResourceID {
	return graphNode.importedResourceID
}

// Participant returns the node name and state.
func (graphNode GraphNode) Participant() Participant { return graphNode.participant }

// Share returns the contract context of a shared-in Device.
func (graphNode GraphNode) Share() (ShareContext, bool) {
	return graphNode.share, graphNode.hasShare
}

// key returns the node identity used to match paths.
func (graphNode GraphNode) key() string {
	switch graphNode.kind {
	case GraphNodeKindDevice:
		return "device:" + graphNode.deviceID.String()
	case GraphNodeKindResource:
		return "resource:" + graphNode.resourceID.String()
	default:
		return "imported:" + graphNode.importedResourceID.String()
	}
}

// IsValid reports whether exactly the identity of its kind is set.
func (graphNode GraphNode) IsValid() bool {
	if !graphNode.participant.IsValid() || graphNode.participant.State() == ParticipantStateMissing {
		return false
	}
	device, resourceSet, imported := graphNode.deviceID.IsValid(), graphNode.resourceID.IsValid(),
		graphNode.importedResourceID.IsValid()
	switch graphNode.kind {
	case GraphNodeKindDevice:
		return device && !resourceSet && !imported && !graphNode.hasShare
	case GraphNodeKindResource:
		return !device && resourceSet && !imported && !graphNode.hasShare
	case GraphNodeKindImportedResource:
		return !device && !resourceSet && imported && graphNode.hasShare && graphNode.share.IsValid()
	default:
		return false
	}
}

// GraphPageParams contains one repeatable-read page of the effective graph.
type GraphPageParams struct {
	Scope                 network.Scope
	Revision              RevisionVector
	HasActiveRelease      bool
	ReleaseID             publication.ReleaseID
	CompilerFormatVersion int
	SemanticHash          publication.SemanticHash
	Nodes                 []GraphNode
	Paths                 []Path
	// MatchingPaths counts every edge that matches the filter in the
	// revision, across all pages.
	MatchingPaths int
	// HasMore reports that edges remain after the last path of this page.
	HasMore bool
}

// GraphPage is one validated, revision-bound page of the effective graph.
type GraphPage struct {
	scope                 network.Scope
	revision              RevisionVector
	hasActiveRelease      bool
	releaseID             publication.ReleaseID
	compilerFormatVersion int
	semanticHash          publication.SemanticHash
	nodes                 []GraphNode
	paths                 []Path
	matchingPaths         int
	next                  GraphCursor
}

// NewGraphPage validates a page against the query it answers: every path
// matches the filter, follows the cursor in projection order, and names only
// nodes listed in the page.
func NewGraphPage(query GraphQuery, params GraphPageParams) (GraphPage, error) {
	if !query.IsValid() {
		return GraphPage{}, ErrInvalidQuery
	}
	page := GraphPage{
		scope: params.Scope, revision: params.Revision, hasActiveRelease: params.HasActiveRelease,
		releaseID: params.ReleaseID, compilerFormatVersion: params.CompilerFormatVersion,
		semanticHash: params.SemanticHash, nodes: slices.Clone(params.Nodes),
		paths: clonePaths(params.Paths), matchingPaths: params.MatchingPaths,
	}
	if !query.cursor.IsZero() && (query.cursor.legacy ||
		query.cursor.policyRevision != params.Revision.PolicyRevision() ||
		query.cursor.groupRevision != params.Revision.GroupRevision()) {
		return GraphPage{}, ErrStaleGraphCursor
	}
	if params.HasMore {
		if len(page.paths) == 0 {
			return GraphPage{}, ErrInvalidSnapshot
		}
		page.next = GraphCursor{
			policyRevision:  params.Revision.PolicyRevision(),
			groupRevision:   params.Revision.GroupRevision(),
			afterProjection: page.paths[len(page.paths)-1].ProjectionID(),
			hasContinuation: true,
		}
	}
	if !page.validFor(query) {
		return GraphPage{}, ErrInvalidSnapshot
	}
	return page, nil
}

func (page GraphPage) validFor(query GraphQuery) bool {
	if page.scope != query.scope || !page.revision.IsValid() || len(page.paths) > query.pageSize ||
		page.matchingPaths < len(page.paths) {
		return false
	}
	if page.hasActiveRelease != (page.releaseID.IsValid() && page.compilerFormatVersion > 0) {
		return false
	}
	if !page.hasActiveRelease && (len(page.paths) > 0 || page.matchingPaths > 0) {
		return false
	}
	nodes := make(map[string]GraphNode, len(page.nodes))
	for _, graphNode := range page.nodes {
		if !graphNode.IsValid() {
			return false
		}
		if _, duplicate := nodes[graphNode.key()]; duplicate {
			return false
		}
		nodes[graphNode.key()] = graphNode
	}
	used := make(map[string]struct{}, len(page.nodes))
	previous := query.cursor.afterProjection
	for index, path := range page.paths {
		if !path.IsValid() || !pathMatchesFilter(path, query) {
			return false
		}
		if (index > 0 || !query.cursor.IsZero()) &&
			strings.Compare(path.ProjectionID().String(), previous.String()) <= 0 {
			return false
		}
		previous = path.ProjectionID()
		for _, key := range pathNodeKeys(path) {
			if _, listed := nodes[key]; !listed {
				return false
			}
			used[key] = struct{}{}
		}
	}
	return len(used) == len(nodes)
}

func pathMatchesFilter(path Path, query GraphQuery) bool {
	if protocol, filtered := query.Protocol(); filtered && path.Protocol() != protocol {
		return false
	}
	deviceID, filtered := query.DeviceID()
	if !filtered {
		return true
	}
	return path.SourceNodeID() == deviceID ||
		(path.SelectorKind() == SelectorKindDevice && path.DestinationNodeID() == deviceID)
}

// pathNodeKeys returns the nodes one path connects. A Resource path names
// the Resource, not its backing Device.
func pathNodeKeys(path Path) []string {
	source := "device:" + path.SourceNodeID().String()
	switch path.SelectorKind() {
	case SelectorKindResource, SelectorKindResourceGroup:
		return []string{source, "resource:" + path.DestinationResourceID().String()}
	case SelectorKindImportedResource:
		return []string{source, "imported:" + path.DestinationImportedResourceID().String()}
	default:
		return []string{source, "device:" + path.DestinationNodeID().String()}
	}
}

// Scope returns the exact Network scope.
func (page GraphPage) Scope() network.Scope { return page.scope }

// Revision returns the authority vector the page was read at.
func (page GraphPage) Revision() RevisionVector { return page.revision }

// ActiveRelease returns the release identity and false when none is active.
func (page GraphPage) ActiveRelease() (publication.ReleaseID, int, publication.SemanticHash, bool) {
	return page.releaseID, page.compilerFormatVersion, page.semanticHash, page.hasActiveRelease
}

// Nodes returns the participants the page's paths connect.
func (page GraphPage) Nodes() []GraphNode { return slices.Clone(page.nodes) }

// Paths returns the compiled edges of the page in projection order.
func (page GraphPage) Paths() []Path { return clonePaths(page.paths) }

// MatchingPaths counts every edge that matches the filter in this revision.
func (page GraphPage) MatchingPaths() int { return page.matchingPaths }

// Next returns the continuation cursor and false on the last page.
func (page GraphPage) Next() (GraphCursor, bool) { return page.next, page.next.hasContinuation }

// GraphReader loads one freshly authorized page of the effective graph.
type GraphReader interface {
	ReadGraph(context.Context, accountsession.Session, GraphQuery, time.Time) (GraphPage, error)
}

// Graph returns one page of edges derived exclusively from the active
// compiled policy, with the participants they connect.
func (service *Service) Graph(
	ctx context.Context,
	session accountsession.Session,
	query GraphQuery,
) (GraphPage, error) {
	if ctx == nil || service == nil || service.clock == nil || !session.IsValid() || !query.IsValid() {
		return GraphPage{}, ErrInvalidQuery
	}
	if service.graphReader == nil {
		return GraphPage{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return GraphPage{}, errors.Join(ErrUnavailable, err)
	}
	evaluatedAt := service.clock.Now().UTC()
	if evaluatedAt.IsZero() {
		return GraphPage{}, ErrUnavailable
	}
	return service.graphReader.ReadGraph(ctx, session, query, evaluatedAt)
}
