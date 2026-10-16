package history_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/audit/history"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

// stubStore fills the default window from its database time and refuses an
// incomplete window, as the PostgreSQL store does.
type stubStore struct {
	databaseTime time.Time
	query        history.Query
	page         history.Page
	err          error
}

func (store *stubStore) List(_ context.Context, _ accountsession.Session, query history.Query) (history.Page, error) {
	at := store.databaseTime
	if at.IsZero() {
		at = time.Date(2026, 10, 7, 5, 0, 0, 0, time.UTC)
	}
	query = query.WithDefaultWindow(at)
	store.query = query
	if !query.IsValid() {
		return history.Page{}, history.ErrInvalid
	}
	page := store.page
	page.Since, page.Until, page.ReadAt = query.Since, query.Until, at
	return page, store.err
}

func newID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testSession(t *testing.T, now time.Time) accountsession.Session {
	t.Helper()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: accountsession.ID(newID(t)), DeploymentID: deployment.ID(newID(t)), PrincipalID: identity.PrincipalID(newID(t)),
		IdentitySubjectID: accountsession.IdentitySubjectID(newID(t)), LoginWorkspaceID: workspace.ID(newID(t)),
		HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test",
		AMR: []string{"mfa"}, Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func sealedRecord(t *testing.T) audit.Record {
	t.Helper()
	record := audit.Record{
		RecordVersion: audit.RecordVersion, EventID: newID(t).String(), EventTime: "2026-10-07T04:05:06.123456Z",
		StreamID: newID(t).String(), Sequence: 3, WorkspaceID: newID(t).String(), ChangeID: newID(t).String(),
		ActorKind: audit.ActorSystem, Action: "workspace.renamed", Permission: "workspace.update",
		Result: audit.ResultSucceeded, TargetKind: "workspace", TargetID: newID(t).String(), PayloadVersion: 1,
		Payload: map[string]any{}, PayloadCanonical: "{}",
		Integrity: audit.RecordIntegrity{Status: audit.IntegritySealed, HashVersion: audit.SealHashVersion,
			PreviousSeal: hex.EncodeToString(make([]byte, 32))},
	}
	material, err := record.SealMaterial()
	if err != nil {
		t.Fatal(err)
	}
	seal, err := audit.Seal(material)
	if err != nil {
		t.Fatal(err)
	}
	record.Integrity.Seal = hex.EncodeToString(seal[:])
	return record
}

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()
	cursor := history.Cursor{OccurredAt: time.Date(2026, 10, 7, 4, 5, 6, 123456000, time.UTC), EventID: newID(t)}
	parsed, err := history.ParseCursor(cursor.Token())
	if err != nil || !parsed.OccurredAt.Equal(cursor.OccurredAt) || parsed.EventID != cursor.EventID {
		t.Fatalf("ParseCursor(Token()) = %+v, %v; want %+v", parsed, err, cursor)
	}
	for _, token := range []string{"", "a1.", "b1." + cursor.Token()[3:], "a1.!!", cursor.Token() + "x"} {
		if _, err := history.ParseCursor(token); !errors.Is(err, history.ErrInvalid) {
			t.Errorf("ParseCursor(%q) error = %v, want ErrInvalid", token, err)
		}
	}
}

func TestListAppliesDefaultsAndRechecksSeals(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 7, 5, 0, 0, 0, time.UTC)
	good, tampered, legacy := sealedRecord(t), sealedRecord(t), sealedRecord(t)
	tampered.Action = "workspace.created"
	legacy.Integrity = audit.RecordIntegrity{Status: audit.IntegrityLegacyUnsealed}
	// The database clock runs behind this host's: the default window ends at
	// the database's time, never the host's.
	databaseTime := now.Add(-2 * time.Minute)
	store := &stubStore{databaseTime: databaseTime, page: history.Page{Records: []audit.Record{good, tampered, legacy}}}
	service, err := history.NewService(store, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	query := history.Query{WorkspaceID: workspace.ID(newID(t))}
	page, err := service.List(context.Background(), testSession(t, now), query)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if !store.query.Until.Equal(databaseTime) || !store.query.Since.Equal(databaseTime.Add(-history.DefaultWindow)) ||
		store.query.PageSize != history.DefaultPageSize || !page.Until.Equal(databaseTime) ||
		!page.Since.Equal(databaseTime.Add(-history.DefaultWindow)) {
		t.Fatalf("store query = %+v, page window %s..%s, want the database's default window and page size",
			store.query, page.Since, page.Until)
	}
	got := []string{page.Records[0].Integrity.Status, page.Records[1].Integrity.Status, page.Records[2].Integrity.Status}
	want := []string{audit.IntegritySealed, audit.IntegritySealMismatch, audit.IntegrityLegacyUnsealed}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("integrity statuses = %v, want %v", got, want)
		}
	}
}

func TestListRejectsInvalidQueries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 7, 5, 0, 0, 0, time.UTC)
	service, err := history.NewService(&stubStore{}, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	base := history.Query{WorkspaceID: workspace.ID(newID(t))}
	cases := map[string]func(*history.Query){
		"no workspace":    func(q *history.Query) { q.WorkspaceID = workspace.ID{} },
		"reversed window": func(q *history.Query) { q.Since = now.Add(time.Hour) },
		"window too long": func(q *history.Query) { q.Since = now.Add(-history.MaximumWindow - time.Hour) },
		"reversed full window": func(q *history.Query) {
			q.Since, q.Until = now.Add(time.Hour), now
		},
		"full window too long": func(q *history.Query) {
			q.Since, q.Until = now.Add(-history.MaximumWindow-time.Hour), now
		},
		"page too large":  func(q *history.Query) { q.PageSize = history.MaximumPageSize + 1 },
		"bad kind":        func(q *history.Query) { q.TargetKinds = []string{"Share Offer"} },
		"bad action":      func(q *history.Query) { q.Action = "share offer" },
		"bad result":      func(q *history.Query) { q.Result = "ok" },
		"system actor id": func(q *history.Query) { q.ActorKind, q.ActorID = audit.ActorSystem, newID(t) },
		"unknown actor":   func(q *history.Query) { q.ActorKind = "robot" },
		"too many kinds": func(q *history.Query) {
			q.TargetKinds = make([]string, history.MaximumTargetKinds+1)
			for index := range q.TargetKinds {
				q.TargetKinds[index] = "share_offer"
			}
		},
	}
	for name, mutate := range cases {
		query := base
		mutate(&query)
		if _, err := service.List(context.Background(), testSession(t, now), query); !errors.Is(err, history.ErrInvalid) {
			t.Errorf("List(%s) error = %v, want ErrInvalid", name, err)
		}
	}
	expired := testSession(t, now.Add(-3*time.Hour))
	if _, err := service.List(context.Background(), expired, base); !errors.Is(err, history.ErrForbidden) {
		t.Errorf("List(expired session) error = %v, want ErrForbidden", err)
	}
}

// stubExportStore fills the default window from the time on the database
// clock of each chunk's read, which advances between chunks.
type stubExportStore struct {
	databaseTime time.Time
	queries      []history.ExportQuery
}

func (store *stubExportStore) ExportChunk(_ context.Context, _ accountsession.Session,
	query history.ExportQuery, after *history.Cursor, _ int) (history.Page, error) {
	at := store.databaseTime.Add(time.Duration(len(store.queries)) * time.Second)
	query = query.WithDefaultWindow(at)
	store.queries = append(store.queries, query)
	if !query.IsValid() {
		return history.Page{}, history.ErrInvalid
	}
	page := history.Page{Records: []audit.Record{}, Actors: map[string]string{}, Since: query.Since,
		Until: query.Until, ReadAt: at}
	if after == nil {
		page.Next = &history.Cursor{OccurredAt: query.Since.Add(time.Hour), EventID: publicid.ID{1}}
	}
	return page, nil
}

func TestExportFixesTheDefaultWindowOnTheDatabaseClock(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 7, 5, 0, 0, 0, time.UTC)
	databaseTime := now.Add(3 * time.Minute)
	store := &stubExportStore{databaseTime: databaseTime}
	exporter, err := history.NewExporter(store, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	export, err := exporter.Export(context.Background(), testSession(t, now),
		history.ExportQuery{WorkspaceID: workspace.ID(newID(t))})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	want := history.ExportQuery{WorkspaceID: export.Query.WorkspaceID,
		Since: databaseTime.Add(-history.DefaultWindow), Until: databaseTime}
	if len(store.queries) != 2 || store.queries[0] != want || store.queries[1] != want ||
		export.Query != want || !export.GeneratedAt.Equal(databaseTime) {
		t.Fatalf("export query %+v at %s; chunk queries %+v; want %+v at %s",
			export.Query, export.GeneratedAt, store.queries, want, databaseTime)
	}
	reversed := history.ExportQuery{WorkspaceID: export.Query.WorkspaceID, Since: databaseTime.Add(time.Hour)}
	if _, err := exporter.Export(context.Background(), testSession(t, now), reversed); !errors.Is(err, history.ErrInvalid) {
		t.Fatalf("Export(since after the database's present) error = %v, want ErrInvalid", err)
	}
}
