package accessgraph_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

func TestGraphCursorRoundTripsAndRejectsTampering(t *testing.T) {
	t.Parallel()

	page := graphPageFixture(t, graphQueryFixture(t, accessgraph.GraphQueryParams{PageSize: 1}), true)
	next, hasNext := page.Next()
	if !hasNext || next.PolicyRevision() != 6 || next.GroupRevision() != 9 {
		t.Fatalf("Next() = %+v, %t", next, hasNext)
	}
	parsed, err := accessgraph.ParseGraphCursor(next.String())
	if err != nil || parsed != next {
		t.Fatalf("ParseGraphCursor(Next) = %+v, %v", parsed, err)
	}
	if first, err := accessgraph.ParseGraphCursor(""); err != nil || !first.IsZero() {
		t.Fatalf("ParseGraphCursor(empty) = %+v, %v", first, err)
	}
	for name, token := range map[string]string{
		"not base64":       "%%%",
		"unknown field":    graphCursorToken(`{"v":1,"r":6,"p":"01890f00-0000-7000-8000-000000001001","x":1}`),
		"wrong version":    graphCursorToken(`{"v":3,"r":6,"g":1,"p":"01890f00-0000-7000-8000-000000001001"}`),
		"v2 without group": graphCursorToken(`{"v":2,"r":6,"p":"01890f00-0000-7000-8000-000000001001"}`),
		"v1 with group":    graphCursorToken(`{"v":1,"r":6,"g":1,"p":"01890f00-0000-7000-8000-000000001001"}`),
		"negative group":   graphCursorToken(`{"v":2,"r":6,"g":-1,"p":"01890f00-0000-7000-8000-000000001001"}`),
		"zero revision":    graphCursorToken(`{"v":1,"r":0,"p":"01890f00-0000-7000-8000-000000001001"}`),
		"bad projection":   graphCursorToken(`{"v":1,"r":6,"p":"not-a-uuid"}`),
		"trailing data":    graphCursorToken(`{"v":1,"r":6,"p":"01890f00-0000-7000-8000-000000001001"} {}`),
		"oversized":        strings.Repeat("a", 300),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := accessgraph.ParseGraphCursor(token); !errors.Is(err, accessgraph.ErrInvalidQuery) {
				t.Fatalf("ParseGraphCursor() error = %v", err)
			}
		})
	}
}

func TestGraphQueryIsBounded(t *testing.T) {
	t.Parallel()

	scope := accessGraphScopeFixture(t)
	defaulted, err := accessgraph.NewGraphQuery(accessgraph.GraphQueryParams{Scope: scope})
	if err != nil || defaulted.PageSize() != accessgraph.DefaultGraphPageSize {
		t.Fatalf("default page size = %d, %v", defaulted.PageSize(), err)
	}
	for name, params := range map[string]accessgraph.GraphQueryParams{
		"missing scope":    {PageSize: 10},
		"negative page":    {Scope: scope, PageSize: -1},
		"oversized page":   {Scope: scope, PageSize: accessgraph.MaximumGraphPageSize + 1},
		"unknown protocol": {Scope: scope, Protocol: policy.Protocol(99)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := accessgraph.NewGraphQuery(params); !errors.Is(err, accessgraph.ErrInvalidQuery) {
				t.Fatalf("NewGraphQuery() error = %v", err)
			}
		})
	}
}

func TestGraphPageRejectsInconsistentPages(t *testing.T) {
	t.Parallel()

	tcp := graphPathFixture(t, 1, 301, 302, policy.ProtocolTCP)
	udp := graphPathFixture(t, 2, 303, 302, policy.ProtocolUDP)
	nodes := graphDeviceNodes(t, 301, 302, 303)
	revision := graphRevisionFixture(t, 6)
	release := graphReleaseFixture(t)
	tests := []struct {
		name   string
		query  accessgraph.GraphQueryParams
		params accessgraph.GraphPageParams
		want   error
	}{
		{
			name:   "path for another protocol",
			query:  accessgraph.GraphQueryParams{Protocol: policy.ProtocolTCP},
			params: graphPageParams(t, revision, release, nodes, []accessgraph.Path{tcp, udp}, 2),
			want:   accessgraph.ErrInvalidSnapshot,
		},
		{
			name:   "path for another Device",
			query:  accessgraph.GraphQueryParams{DeviceID: accessGraphNodeID(t, 301)},
			params: graphPageParams(t, revision, release, nodes, []accessgraph.Path{udp}, 1),
			want:   accessgraph.ErrInvalidSnapshot,
		},
		{
			name:   "paths out of projection order",
			params: graphPageParams(t, revision, release, nodes, []accessgraph.Path{udp, tcp}, 2),
			want:   accessgraph.ErrInvalidSnapshot,
		},
		{
			name:   "path to an unlisted node",
			params: graphPageParams(t, revision, release, graphDeviceNodes(t, 301, 302), []accessgraph.Path{udp}, 1),
			want:   accessgraph.ErrInvalidSnapshot,
		},
		{
			name:   "node no path uses",
			params: graphPageParams(t, revision, release, nodes, []accessgraph.Path{tcp}, 1),
			want:   accessgraph.ErrInvalidSnapshot,
		},
		{
			name:   "more paths than the page size",
			query:  accessgraph.GraphQueryParams{PageSize: 1},
			params: graphPageParams(t, revision, release, nodes, []accessgraph.Path{tcp, udp}, 2),
			want:   accessgraph.ErrInvalidSnapshot,
		},
		{
			name:   "count below the page",
			params: graphPageParams(t, revision, release, nodes, []accessgraph.Path{tcp, udp}, 1),
			want:   accessgraph.ErrInvalidSnapshot,
		},
		{
			name: "paths without an active release",
			params: accessgraph.GraphPageParams{
				Scope: accessGraphScopeFixture(t), Revision: revision,
				Nodes: nodes, Paths: []accessgraph.Path{tcp, udp}, MatchingPaths: 2,
			},
			want: accessgraph.ErrInvalidSnapshot,
		},
		{
			name: "cursor from another policy revision",
			query: accessgraph.GraphQueryParams{
				Cursor: graphCursorFixture(t, 5, tcp.ProjectionID()),
			},
			params: graphPageParams(t, revision, release, graphDeviceNodes(t, 303, 302), []accessgraph.Path{udp}, 2),
			want:   accessgraph.ErrStaleGraphCursor,
		},
		{
			name: "cursor from another group revision",
			query: accessgraph.GraphQueryParams{
				Cursor: graphCursorAt(t, `{"v":2,"r":6,"g":8,"p":"`+tcp.ProjectionID().String()+`"}`),
			},
			params: graphPageParams(t, revision, release, graphDeviceNodes(t, 303, 302), []accessgraph.Path{udp}, 2),
			want:   accessgraph.ErrStaleGraphCursor,
		},
		{
			name: "cursor issued before group edges",
			query: accessgraph.GraphQueryParams{
				Cursor: graphCursorAt(t, `{"v":1,"r":6,"p":"`+tcp.ProjectionID().String()+`"}`),
			},
			params: graphPageParams(t, revision, release, graphDeviceNodes(t, 303, 302), []accessgraph.Path{udp}, 2),
			want:   accessgraph.ErrStaleGraphCursor,
		},
		{
			name: "path at or before the cursor",
			query: accessgraph.GraphQueryParams{
				Cursor: graphCursorFixture(t, 6, udp.ProjectionID()),
			},
			params: graphPageParams(t, revision, release, graphDeviceNodes(t, 303, 302), []accessgraph.Path{udp}, 2),
			want:   accessgraph.ErrInvalidSnapshot,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			query := graphQueryFixture(t, test.query)
			if _, err := accessgraph.NewGraphPage(query, test.params); !errors.Is(err, test.want) {
				t.Fatalf("NewGraphPage() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestGraphPageKeepsDeviceFilterOnEitherEnd(t *testing.T) {
	t.Parallel()

	outgoing := graphPathFixture(t, 1, 301, 302, policy.ProtocolTCP)
	incoming := graphPathFixture(t, 2, 303, 301, policy.ProtocolTCP)
	query := graphQueryFixture(t, accessgraph.GraphQueryParams{DeviceID: accessGraphNodeID(t, 301)})
	page, err := accessgraph.NewGraphPage(query, graphPageParams(
		t, graphRevisionFixture(t, 6), graphReleaseFixture(t), graphDeviceNodes(t, 301, 302, 303),
		[]accessgraph.Path{outgoing, incoming}, 2,
	))
	if err != nil || len(page.Paths()) != 2 || len(page.Nodes()) != 3 || page.MatchingPaths() != 2 {
		t.Fatalf("filtered page = %+v, %v", page, err)
	}
	if _, more := page.Next(); more {
		t.Fatal("last page returned a continuation")
	}
}

func TestGraphServiceRejectsInvalidInputBeforeReading(t *testing.T) {
	t.Parallel()

	reader := &graphReaderStub{}
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: explainReaderStub{}, Clock: graphClock{now: accessGraphTime()}, GraphReader: reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Graph(t.Context(), accountsession.Session{}, graphQueryFixture(t, accessgraph.GraphQueryParams{})); !errors.Is(err, accessgraph.ErrInvalidQuery) {
		t.Fatalf("Graph(invalid session) error = %v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0", reader.calls)
	}
	page, err := service.Graph(t.Context(), accessGraphSessionFixture(t), graphQueryFixture(t, accessgraph.GraphQueryParams{}))
	if err != nil || reader.calls != 1 || !reader.evaluatedAt.Equal(accessGraphTime()) || page.Scope() != accessGraphScopeFixture(t) {
		t.Fatalf("Graph() = %+v, %v (calls %d)", page, err, reader.calls)
	}
	withoutGraph, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: explainReaderStub{}, Clock: graphClock{now: accessGraphTime()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutGraph.Graph(t.Context(), accessGraphSessionFixture(t), graphQueryFixture(t, accessgraph.GraphQueryParams{})); !errors.Is(err, accessgraph.ErrUnavailable) {
		t.Fatalf("Graph(no reader) error = %v", err)
	}
}

type explainReaderStub struct{}

func (explainReaderStub) ReadActive(
	context.Context, accountsession.Session, accessgraph.Query, time.Time,
) (accessgraph.Snapshot, error) {
	return accessgraph.Snapshot{}, accessgraph.ErrUnavailable
}

type graphReaderStub struct {
	calls       int
	evaluatedAt time.Time
}

func (stub *graphReaderStub) ReadGraph(
	_ context.Context,
	_ accountsession.Session,
	query accessgraph.GraphQuery,
	evaluatedAt time.Time,
) (accessgraph.GraphPage, error) {
	stub.calls++
	stub.evaluatedAt = evaluatedAt
	return accessgraph.NewGraphPage(query, accessgraph.GraphPageParams{
		Scope: query.Scope(), Revision: graphRevisionVector(6),
	})
}

type graphClock struct{ now time.Time }

func (clock graphClock) Now() time.Time { return clock.now }

type graphRelease struct {
	id   publication.ReleaseID
	hash publication.SemanticHash
}

func graphQueryFixture(t *testing.T, params accessgraph.GraphQueryParams) accessgraph.GraphQuery {
	t.Helper()
	params.Scope = accessGraphScopeFixture(t)
	query, err := accessgraph.NewGraphQuery(params)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func graphPageFixture(t *testing.T, query accessgraph.GraphQuery, more bool) accessgraph.GraphPage {
	t.Helper()
	params := graphPageParams(t, graphRevisionFixture(t, 6), graphReleaseFixture(t), graphDeviceNodes(t, 301, 302),
		[]accessgraph.Path{graphPathFixture(t, 1, 301, 302, policy.ProtocolTCP)}, 2)
	params.HasMore = more
	page, err := accessgraph.NewGraphPage(query, params)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func graphPageParams(
	t *testing.T,
	revision accessgraph.RevisionVector,
	release graphRelease,
	nodes []accessgraph.GraphNode,
	paths []accessgraph.Path,
	matching int,
) accessgraph.GraphPageParams {
	t.Helper()
	return accessgraph.GraphPageParams{
		Scope: accessGraphScopeFixture(t), Revision: revision, HasActiveRelease: true, ReleaseID: release.id,
		CompilerFormatVersion: 4, SemanticHash: release.hash, Nodes: nodes, Paths: paths,
		MatchingPaths: matching,
	}
}

func graphPathFixture(t *testing.T, sequence, source, destination int, protocol policy.Protocol) accessgraph.Path {
	t.Helper()
	template := accessGraphPathFixture(t, sequence, policy.ProtocolICMP, 0, 0)
	var ranges []policy.PortRange
	if protocol != policy.ProtocolICMP {
		portRange, err := policy.NewPortRange(443, 443)
		if err != nil {
			t.Fatal(err)
		}
		ranges = []policy.PortRange{portRange}
	}
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: template.ProjectionID(), RuleID: template.RuleID(),
		SourceNodeID: accessGraphNodeID(t, source), DestinationNodeID: accessGraphNodeID(t, destination),
		Protocol: protocol, DestinationPortRanges: ranges, SelectorKind: accessgraph.SelectorKindDevice,
	})
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func graphDeviceNodes(t *testing.T, sequences ...int) []accessgraph.GraphNode {
	t.Helper()
	nodes := make([]accessgraph.GraphNode, 0, len(sequences))
	for _, sequence := range sequences {
		graphNode, err := accessgraph.NewGraphNode(accessgraph.GraphNodeParams{
			Kind: accessgraph.GraphNodeKindDevice, DeviceID: accessGraphNodeID(t, sequence),
			Participant: accessGraphParticipant(t, accessgraph.ParticipantStateActive, "device"),
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, graphNode)
	}
	return nodes
}

func graphRevisionFixture(t *testing.T, policyRevision int64) accessgraph.RevisionVector {
	t.Helper()
	vector, err := accessgraph.NewRevisionVector(graphRevisionParams(policyRevision))
	if err != nil {
		t.Fatal(err)
	}
	return vector
}

func graphRevisionVector(policyRevision int64) accessgraph.RevisionVector {
	vector, _ := accessgraph.NewRevisionVector(graphRevisionParams(policyRevision))
	return vector
}

func graphRevisionParams(policyRevision int64) accessgraph.RevisionVectorParams {
	return accessgraph.RevisionVectorParams{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9, PolicyRevision: policyRevision,
		DNSRevision: 2, RouteRevision: 3, SharingRevision: 4, IsolationGeneration: 5,
	}
}

func graphReleaseFixture(t *testing.T) graphRelease {
	t.Helper()
	id, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := publication.NewSemanticHash([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	return graphRelease{id: id, hash: hash}
}

func graphCursorFixture(t *testing.T, policyRevision int64, after publication.ProjectionID) accessgraph.GraphCursor {
	t.Helper()
	return graphCursorAt(t, `{"v":2,"r":`+strconv.FormatInt(policyRevision, 10)+`,"g":9,"p":"`+after.String()+`"}`)
}

func graphCursorAt(t *testing.T, document string) accessgraph.GraphCursor {
	t.Helper()
	cursor, err := accessgraph.ParseGraphCursor(graphCursorToken(document))
	if err != nil {
		t.Fatal(err)
	}
	return cursor
}

func graphCursorToken(document string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(document))
}
