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

type stubStore struct {
	query history.Query
	page  history.Page
	err   error
}

func (store *stubStore) List(_ context.Context, _ accountsession.Session, query history.Query) (history.Page, error) {
	store.query = query
	return store.page, store.err
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
	store := &stubStore{page: history.Page{Records: []audit.Record{good, tampered, legacy}}}
	service, err := history.NewService(store, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	query := history.Query{WorkspaceID: workspace.ID(newID(t))}
	page, err := service.List(context.Background(), testSession(t, now), query)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if !store.query.Until.Equal(now) || !store.query.Since.Equal(now.Add(-history.DefaultWindow)) ||
		store.query.PageSize != history.DefaultPageSize {
		t.Fatalf("store query = %+v, want default window and page size", store.query)
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
