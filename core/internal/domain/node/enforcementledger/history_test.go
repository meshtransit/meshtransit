package enforcementledger

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/workspace"
)

// historyNow is the database clock's present in these tests.
var historyNow = time.Date(2026, time.October, 9, 16, 30, 0, 0, time.UTC)

type fakeHistoryReader struct {
	devices []Evidence
	since   time.Time
	limit   int
	at      time.Time
}

// ReadEnforcementHistory resolves the present and refuses the future on the
// database clock, as the PostgreSQL store does.
func (reader *fakeHistoryReader) ReadEnforcementHistory(_ context.Context, _ accountsession.Session,
	scope network.Scope, at time.Time, _ node.ID, limit int) (HistoryResult, error) {
	reader.limit, reader.at = limit, at
	if at.IsZero() {
		at = historyNow
	}
	if at.After(historyNow) {
		return HistoryResult{}, ErrInvalidRequest
	}
	return HistoryResult{Scope: scope, At: at, RecordedSince: reader.since, Devices: reader.devices}, nil
}

func testSession(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: historyNow.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: historyNow.Add(time.Hour), AbsoluteExpiresAt: historyNow.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func evidenceFor(t *testing.T, index int, state State, from time.Time) Evidence {
	t.Helper()
	enforced := digestA
	if state == StateMismatch {
		enforced = digestB
	}
	return Evidence{DeviceID: testDevice(t, index), State: state, NetworkRevision: 4,
		Delivered: distribution.FilterSummary{Digest: digestA, Grants: 2},
		Enforced:  distribution.FilterSummary{Digest: enforced, Grants: 2},
		AppliedAt: from, ReportedAt: from, ValidFrom: from}
}

func TestHistoryServicePagesAndValidates(t *testing.T) {
	scope := testScope(t)
	from := historyNow.Add(-time.Hour)
	reader := &fakeHistoryReader{since: from, devices: []Evidence{
		evidenceFor(t, 1, StateEnforced, from), evidenceFor(t, 2, StateMismatch, from), evidenceFor(t, 3, StateEnforced, from),
	}}
	service, err := NewHistoryService(reader)
	if err != nil {
		t.Fatal(err)
	}
	// A zero instant asks the reader for the database's present.
	page, err := service.Read(t.Context(), testSession(t), scope, time.Time{}, node.ID{}, 2)
	if err != nil || reader.limit != 3 || !reader.at.IsZero() || !page.At.Equal(historyNow) ||
		len(page.Devices) != 2 || page.Next != page.Devices[1].DeviceID {
		t.Fatalf("page = %+v, %v (limit %d)", page, err, reader.limit)
	}
	if _, err := service.Read(t.Context(), testSession(t), scope, historyNow.Add(time.Minute), node.ID{}, 2); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("future read error = %v", err)
	}
	broken := evidenceFor(t, 1, StateEnforced, from)
	broken.Enforced.Digest = digestB
	for name, devices := range map[string][]Evidence{
		"state disagrees":  {broken},
		"not yet in force": {evidenceFor(t, 1, StateEnforced, historyNow.Add(time.Minute))},
		"out of order":     {evidenceFor(t, 2, StateEnforced, from), evidenceFor(t, 1, StateEnforced, from)},
	} {
		reader.devices = devices
		if _, err := service.Read(t.Context(), testSession(t), scope, historyNow, node.ID{}, 10); !errors.Is(err, ErrInvalidResult) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}
