package ledger

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type historyReaderFunc func(context.Context, accountsession.Session, network.Scope, Query) (Result, error)

func (read historyReaderFunc) ReadHistory(ctx context.Context, session accountsession.Session, scope network.Scope,
	query Query) (Result, error) {
	return read(ctx, session, scope, query)
}

func mustNode(t *testing.T, value string) node.ID {
	t.Helper()
	id, err := node.ParseID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustPublic(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func edgeAt(t *testing.T, key byte, from time.Time) Edge {
	t.Helper()
	var edgeKey EdgeKey
	edgeKey[0] = key
	return Edge{Key: edgeKey, AccessRuleID: mustPublic(t, "01890f00-0000-7000-8000-000000000501"),
		SelectorKind: SelectorDevice, SourceDeviceID: mustNode(t, "01890f00-0000-7000-8000-000000000301"),
		DestinationDeviceID: mustNode(t, "01890f00-0000-7000-8000-000000000302"), Protocol: policy.ProtocolTCP,
		ValidFromRevision: 3, ValidFrom: from}
}

func testSession(t *testing.T) accountsession.Session {
	t.Helper()
	now := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestEdgeKeyRoundTripsCanonicalHex(t *testing.T) {
	t.Parallel()
	var key EdgeKey
	key[31] = 0xab
	parsed, err := ParseEdgeKey(key.String())
	if err != nil || parsed != key {
		t.Fatalf("ParseEdgeKey() = %v %v", parsed, err)
	}
	for _, value := range []string{"", "AB", key.String()[:62], "zz" + key.String()[2:]} {
		if _, err := ParseEdgeKey(value); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("ParseEdgeKey(%q) accepted", value)
		}
	}
}

func TestValidResultRejectsEdgesOutOfEffectOrOrder(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "01890f00-0000-7000-8000-000000000201")
	at := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	query := Query{At: at, Limit: 3}
	base := Result{Scope: scope, At: at, RecordedSince: at.Add(-time.Hour), NetworkRevision: 4,
		Edges: []Edge{edgeAt(t, 1, at.Add(-time.Minute)), edgeAt(t, 2, at)}}
	if !validResult(base, scope, query) {
		t.Fatal("valid result rejected")
	}
	closed := edgeAt(t, 3, at.Add(-time.Hour))
	closed.ValidToRevision, closed.ValidTo = 4, at.Add(time.Second)
	if !validResult(Result{Scope: scope, At: at, RecordedSince: at.Add(-time.Hour), Edges: []Edge{closed}}, scope, query) {
		t.Fatal("edge closed after the instant rejected")
	}
	imported := edgeAt(t, 4, at.Add(-time.Minute))
	imported.SelectorKind, imported.DestinationDeviceID = SelectorImportedResource, node.ID{}
	imported.ImportedResourceID = mustPublic(t, "01890f00-0000-7000-8000-000000000601")
	imported.TrustContractID = mustPublic(t, "01890f00-0000-7000-8000-000000000701")
	if !validResult(Result{Scope: scope, At: at, RecordedSince: at, Edges: []Edge{imported}}, scope, query) {
		t.Fatal("imported edge rejected")
	}

	mutations := map[string]func(*Result){
		"future edge":         func(result *Result) { result.Edges[1].ValidFrom = at.Add(time.Second) },
		"closed before":       func(result *Result) { result.Edges[0].ValidToRevision, result.Edges[0].ValidTo = 4, at },
		"expired":             func(result *Result) { result.Edges[0].ExpiresAt = at },
		"reordered":           func(result *Result) { result.Edges[0], result.Edges[1] = result.Edges[1], result.Edges[0] },
		"other instant":       func(result *Result) { result.At = at.Add(time.Second) },
		"edges before ledger": func(result *Result) { result.RecordedSince = time.Time{} },
		"imported shape":      func(result *Result) { result.Edges[0].SelectorKind = SelectorImportedResource },
		"unknown protocol":    func(result *Result) { result.Edges[0].Protocol = policy.ProtocolUnknown },
		"future snapshot": func(result *Result) {
			result.Snapshot = &Snapshot{ID: mustPublic(t, "01890f00-0000-7000-8000-000000000801"), NetworkRevision: 4,
				EffectiveAt: at.Add(time.Second), Digest: string(make([]byte, 64))}
		},
	}
	for name, mutate := range mutations {
		result := base
		result.Edges = append([]Edge(nil), base.Edges...)
		mutate(&result)
		if validResult(result, scope, query) {
			t.Errorf("%s accepted", name)
		}
	}
	// A zero At asks for the present: the reader's instant answers it, and
	// edges are judged at that instant.
	present := Query{Limit: 3}
	if !validResult(base, scope, present) {
		t.Error("present result rejected")
	}
	noInstant := base
	noInstant.At = time.Time{}
	if validResult(noInstant, scope, present) {
		t.Error("present result without its instant accepted")
	}
	early := base
	early.At = at.Add(-2 * time.Minute)
	if validResult(early, scope, present) {
		t.Error("edge after the reader's present accepted")
	}
	filtered := Query{At: at, Limit: 3, Source: mustNode(t, "01890f00-0000-7000-8000-000000000399")}
	if validResult(base, scope, filtered) {
		t.Error("edge outside the source filter accepted")
	}
}

func TestServiceReadsPresentPageWithContinuation(t *testing.T) {
	t.Parallel()
	session := testSession(t)
	scope := testScope(t, "01890f00-0000-7000-8000-000000000201")
	// databaseNow stands in for the reader's database clock: it answers a
	// zero At with its present and rejects an instant after it, as SQL does.
	databaseNow := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	var got Query
	reader := historyReaderFunc(func(_ context.Context, _ accountsession.Session, _ network.Scope,
		query Query) (Result, error) {
		got = query
		at := query.At
		if at.IsZero() {
			at = databaseNow
		}
		if at.After(databaseNow) {
			return Result{}, ErrInvalidRequest
		}
		return Result{Scope: scope, At: at, RecordedSince: databaseNow.Add(-time.Hour), NetworkRevision: 5,
			Edges: []Edge{edgeAt(t, 1, databaseNow.Add(-time.Hour)), edgeAt(t, 2, databaseNow.Add(-time.Hour))}}, nil
	})
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.Read(t.Context(), session, scope, Query{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	// The present is the reader's: the service sends no host-clock instant.
	if !got.At.IsZero() || !page.At.Equal(databaseNow) || got.Limit != 2 || len(page.Edges) != 1 ||
		page.Next != page.Edges[0].Key || page.NetworkRevision != 5 {
		t.Fatalf("query = %+v page = %+v", got, page)
	}
	if _, err := service.Read(t.Context(), session, scope, Query{At: databaseNow.Add(time.Second), Limit: 1}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("future instant error = %v", err)
	}
	past := databaseNow.Add(-time.Minute).Add(123 * time.Nanosecond)
	if page, err := service.Read(t.Context(), session, scope, Query{At: past, Limit: 1}); err != nil ||
		!got.At.Equal(past.Truncate(time.Microsecond)) || !page.At.Equal(got.At) {
		t.Fatalf("past instant = %+v, %v (query %+v)", page, err, got)
	}
	if _, err := service.Read(t.Context(), session, scope, Query{Limit: MaximumPageSize + 1}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized page error = %v", err)
	}
}

func TestValidResultChecksSiteEdges(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "01890f00-0000-7000-8000-000000000201")
	at := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	query := Query{At: at, Limit: 3}
	siteEdge := func() Edge {
		edge := edgeAt(t, 5, at.Add(-time.Minute))
		edge.SelectorKind, edge.DestinationDeviceID = SelectorSite, node.ID{}
		edge.SiteID = mustPublic(t, "01890f00-0000-7000-8000-000000000971")
		edge.Prefixes = []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}
		return edge
	}
	if !validResult(Result{Scope: scope, At: at, RecordedSince: at, Edges: []Edge{siteEdge()}}, scope, query) {
		t.Fatal("Site edge rejected")
	}
	for name, mutate := range map[string]func(*Edge){
		"no Site":            func(edge *Edge) { edge.SiteID = publicid.ID{} },
		"no prefixes":        func(edge *Edge) { edge.Prefixes = nil },
		"destination Device": func(edge *Edge) { edge.DestinationDeviceID = mustNode(t, "01890f00-0000-7000-8000-000000000302") },
		"Device kind": func(edge *Edge) {
			edge.SelectorKind, edge.DestinationDeviceID = SelectorDevice, mustNode(t, "01890f00-0000-7000-8000-000000000302")
		},
	} {
		edge := siteEdge()
		mutate(&edge)
		if validResult(Result{Scope: scope, At: at, RecordedSince: at, Edges: []Edge{edge}}, scope, query) {
			t.Errorf("%s accepted", name)
		}
	}
}
