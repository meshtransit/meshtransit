package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/audit/history"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/invitation"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/publicid"
)

// clockStoreDatabaseTime is the database clock's time in these tests, far
// from any host clock, so a store that used its host's time would not pass it.
var clockStoreDatabaseTime = time.Date(2031, time.January, 2, 3, 4, 5, 678000, time.UTC)

// errClockStoreStop ends a unit of work right after the call under test.
var errClockStoreStop = errors.New("clock store test: stop after the recorded call")

type clockStoreCall struct {
	query     string
	arguments []any
}

// clockStoreTransaction records every statement of one unit of work. It
// answers the database clock read, the scope statements and nothing else, so
// each store stops right after the statement under test.
type clockStoreTransaction struct {
	calls []clockStoreCall
}

func (*clockStoreTransaction) Exec(context.Context, string, ...any) error { return nil }

func (transaction *clockStoreTransaction) QueryRow(_ context.Context, query string,
	arguments ...any) fakeAccountSessionRow {
	transaction.calls = append(transaction.calls, clockStoreCall{query: query, arguments: arguments})
	switch query {
	case transactionTimeSQL:
		return fakeAccountSessionRow{values: []any{clockStoreDatabaseTime}}
	case setResourceAuthorityScopeSQL:
		return fakeAccountSessionRow{values: []any{int64(1), int64(2)}}
	case resolveLogoutScopeSQL:
		return fakeAccountSessionRow{values: []any{"01890f00-0000-7000-8000-000000000101", testNetworkMemberNetwork}}
	default:
		return fakeAccountSessionRow{err: errClockStoreStop}
	}
}

func (*clockStoreTransaction) Commit(context.Context) error   { return nil }
func (*clockStoreTransaction) Rollback(context.Context) error { return nil }

// call returns the arguments of the one statement named query, which must
// follow exactly one database clock read in the same unit of work.
func (transaction *clockStoreTransaction) call(t *testing.T, query string) []any {
	t.Helper()
	timeReads, found := 0, -1
	for index, call := range transaction.calls {
		switch call.query {
		case transactionTimeSQL:
			timeReads++
		case query:
			if found >= 0 || timeReads != 1 {
				t.Fatalf("statement %d of %+v: want one database clock read before one call", index, transaction.calls)
			}
			found = index
		}
	}
	if found < 0 || timeReads != 1 {
		t.Fatalf("calls %+v: want one database clock read and the statement under test", transaction.calls)
	}
	return transaction.calls[found].arguments
}

type clockStoreAccountDatabase struct{ transaction *clockStoreTransaction }

func (database clockStoreAccountDatabase) Begin(context.Context) (accountSessionTransaction, error) {
	return accountSessionClockTransaction{database.transaction}, nil
}

// accountSessionClockTransaction adapts the recorder to the account session
// transaction's row type.
type accountSessionClockTransaction struct{ *clockStoreTransaction }

func (transaction accountSessionClockTransaction) QueryRow(ctx context.Context, query string,
	arguments ...any) accountSessionRow {
	return transaction.clockStoreTransaction.QueryRow(ctx, query, arguments...)
}

type clockStoreResourceDatabase struct{ transaction *clockStoreTransaction }

func (database clockStoreResourceDatabase) Begin(context.Context, bool) (resourceAuthorityDatabaseTransaction,
	error) {
	return resourceAuthorityClockTransaction{database.transaction}, nil
}

func (database clockStoreResourceDatabase) BeginRepeatableRead(context.Context) (
	resourceAuthorityDatabaseTransaction, error) {
	return resourceAuthorityClockTransaction{database.transaction}, nil
}

// resourceAuthorityClockTransaction adapts the recorder to the resource
// authority transaction's row type.
type resourceAuthorityClockTransaction struct{ *clockStoreTransaction }

func (transaction resourceAuthorityClockTransaction) QueryRow(ctx context.Context, query string,
	arguments ...any) resourceAuthorityRow {
	return transaction.clockStoreTransaction.QueryRow(ctx, query, arguments...)
}

var clockStoreOptions = AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}

func assertClockStoreArgument(t *testing.T, name string, arguments []any, index int, want time.Time) {
	t.Helper()
	if len(arguments) <= index {
		t.Fatalf("%s: %d arguments, want an argument at %d", name, len(arguments), index)
	}
	got, ok := arguments[index].(time.Time)
	if !ok || !got.Equal(want) {
		t.Fatalf("%s: argument %d = %v, want %s", name, index, arguments[index], want)
	}
}

func TestIdentityStoresPassTheirDatabaseTime(t *testing.T) {
	t.Parallel()
	session := accountSessionManagementScopeSession(t, time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
	scope := testNetworkMemberScope(t)
	workspaceID := scope.WorkspaceID()
	member := mustPublicID(t, testNetworkMemberA)
	correlation := mustPublicID(t, "01890f00-0000-7000-8000-000000000901")
	digest := [32]byte{1}
	machineKey, err := node.NewMachineKey([32]byte{0: 1})
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey([32]byte{0: 2})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	invitationID, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	device, err := node.ParseID(testNetworkMemberDevice)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		query string
		run   func(accountSessionDatabase) error
	}{
		{"invitation list", listWorkspaceInvitationsSQL, func(database accountSessionDatabase) error {
			_, err := (&InvitationStore{database: database, options: clockStoreOptions}).List(
				t.Context(), session, workspaceID)
			return err
		}},
		{"invitation preview", previewWorkspaceInvitationSQL, func(database accountSessionDatabase) error {
			_, err := (&InvitationStore{database: database, options: clockStoreOptions}).PreviewInvitation(
				t.Context(), digest)
			return err
		}},
		{"invitation revoke", changeWorkspaceInvitationSQL, func(database accountSessionDatabase) error {
			_, err := (&InvitationStore{database: database, options: clockStoreOptions}).Change(t.Context(),
				invitation.Change{Session: session, WorkspaceID: workspaceID, InvitationID: invitationID,
					Action: invitation.ActionRevoke, ExpectedVersion: 2, CorrelationID: correlation})
			return err
		}},
		{"member suspend", changeWorkspaceMemberSQL, func(database accountSessionDatabase) error {
			_, err := (&MemberLifecycleStore{database: database, options: clockStoreOptions}).Change(t.Context(),
				memberlifecycle.Change{Session: session, WorkspaceID: workspaceID, MemberID: member,
					Action: memberlifecycle.ActionSuspend, Reason: "left", CorrelationID: correlation})
			return err
		}},
		{"member sessions", revokeWorkspaceMemberSessionsSQL, func(database accountSessionDatabase) error {
			_, err := (&MemberLifecycleStore{database: database, options: clockStoreOptions}).Change(t.Context(),
				memberlifecycle.Change{Session: session, WorkspaceID: workspaceID, MemberID: member,
					Action: memberlifecycle.ActionRevokeSessions, Reason: "lost laptop", CorrelationID: correlation})
			return err
		}},
		{"member removal", removeWorkspaceMemberSQL, func(database accountSessionDatabase) error {
			_, err := (&MemberLifecycleStore{database: database, options: clockStoreOptions}).Remove(t.Context(),
				memberlifecycle.Removal{Session: session, WorkspaceID: workspaceID, MemberID: member,
					Reason: "left", CorrelationID: correlation})
			return err
		}},
		{"Network member list", listNetworkMembersSQL, func(database accountSessionDatabase) error {
			_, err := (&NetworkMemberStore{database: database, options: clockStoreOptions}).ListNetworkMembers(
				t.Context(), memberlifecycle.NetworkMemberQuery{Session: session, Scope: scope, Limit: 10})
			return err
		}},
		{"Network member addition", addNetworkMembersSQL, func(database accountSessionDatabase) error {
			_, err := (&NetworkMemberStore{database: database, options: clockStoreOptions}).AddNetworkMembers(
				t.Context(), memberlifecycle.NetworkAddition{Session: session, Scope: scope,
					MemberIDs: []publicid.ID{member}, CorrelationID: correlation})
			return err
		}},
		{"Network member removal", removeNetworkMemberSQL, func(database accountSessionDatabase) error {
			_, err := (&NetworkMemberStore{database: database, options: clockStoreOptions}).RemoveNetworkMember(
				t.Context(), memberlifecycle.NetworkRemoval{Session: session, Scope: scope, MemberID: member,
					Reason: "left", CorrelationID: correlation})
			return err
		}},
		{"Device lifecycle", changeDeviceLifecycleSQL, func(database accountSessionDatabase) error {
			_, err := (&DeviceLifecycleStore{database: database, options: clockStoreOptions}).Change(t.Context(),
				devicelifecycle.Change{Session: session, Scope: scope, DeviceID: device,
					Action: devicelifecycle.ActionSuspend, ExpectedVersion: 1, Reason: "lost",
					CorrelationID: correlation})
			return err
		}},
		{"Device logout", logoutDeviceSQL, func(database accountSessionDatabase) error {
			_, err := (&DeviceLogoutStore{database: database, options: clockStoreOptions}).LogoutDevice(
				t.Context(), identity)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transaction := &clockStoreTransaction{}
			if err := test.run(clockStoreAccountDatabase{transaction}); err == nil {
				t.Fatal("the recorder ends every unit of work with an error")
			}
			arguments := transaction.call(t, test.query)
			assertClockStoreArgument(t, test.name, arguments, len(arguments)-1, clockStoreDatabaseTime)
		})
	}
}

func TestInvitationLinkExpiresLifetimeAfterTheDatabaseTime(t *testing.T) {
	t.Parallel()
	session := accountSessionManagementScopeSession(t, time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
	digest := [32]byte{1}
	invitationID, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	transaction := &clockStoreTransaction{}
	store := &InvitationStore{database: clockStoreAccountDatabase{transaction}, options: clockStoreOptions}
	if _, err := store.Change(t.Context(), invitation.Change{
		Session: session, WorkspaceID: testNetworkMemberScope(t).WorkspaceID(), InvitationID: invitationID,
		Action: invitation.ActionCreate, Email: "member@example.com", TokenDigest: &digest,
		CorrelationID: mustPublicID(t, "01890f00-0000-7000-8000-000000000901"),
	}); !errors.Is(err, invitation.ErrUnavailable) {
		t.Fatalf("Change() error = %v", err)
	}
	arguments := transaction.call(t, changeWorkspaceInvitationSQL)
	want := clockStoreDatabaseTime.Add(invitation.Lifetime).Truncate(time.Second)
	assertClockStoreArgument(t, "invitation expiry", arguments, 15, want)
	assertClockStoreArgument(t, "invitation evaluation", arguments, 18, clockStoreDatabaseTime)
}

func TestConsoleDeviceReadsPassTheirDatabaseTime(t *testing.T) {
	t.Parallel()
	session := accountSessionManagementScopeSession(t, time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
	scope := testNetworkMemberScope(t)
	for _, test := range []struct {
		name  string
		query string
		run   func(resourceAuthorityDatabase) error
	}{
		{"inventory", readConsoleDeviceInventorySQL, func(database resourceAuthorityDatabase) error {
			_, err := (&ConsoleDeviceInventoryStore{database: database, options: clockStoreOptions}).ReadDevices(
				t.Context(), session, scope, inventory.Query{Limit: 2})
			return err
		}},
		{"names", readConsoleDeviceNamesSQL, func(database resourceAuthorityDatabase) error {
			device, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
			_, err := (&ConsoleDeviceInventoryStore{database: database, options: clockStoreOptions}).ReadDeviceNames(
				t.Context(), session, scope, []node.ID{device})
			return err
		}},
		{"device", readConsoleDeviceSQL, func(database resourceAuthorityDatabase) error {
			device, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
			_, err := (&ConsoleDeviceInventoryStore{database: database, options: clockStoreOptions}).ReadDevice(
				t.Context(), session, scope, device)
			return err
		}},
		{"distribution", readDeviceDistributionSQL, func(database resourceAuthorityDatabase) error {
			device, _ := node.ParseID("01890f00-0000-7000-8000-000000000901")
			_, err := (&DeviceDistributionStore{database: database, options: clockStoreOptions}).ReadTarget(
				t.Context(), session, scope, device)
			return err
		}},
		{"enforcement history", readDeviceEnforcementHistorySQL, func(database resourceAuthorityDatabase) error {
			_, err := (&DeviceEnforcementHistoryStore{database: database, options: clockStoreOptions}).
				ReadEnforcementHistory(t.Context(), session, scope, time.Time{}, node.ID{}, 2)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transaction := &clockStoreTransaction{}
			if err := test.run(clockStoreResourceDatabase{transaction}); err == nil {
				t.Fatal("the recorder ends every unit of work with an error")
			}
			arguments := transaction.call(t, test.query)
			assertClockStoreArgument(t, test.name, arguments, 11, clockStoreDatabaseTime)
			if test.query == readDeviceEnforcementHistorySQL {
				// A zero instant reads the database's present.
				assertClockStoreArgument(t, test.name+" instant", arguments, 12, clockStoreDatabaseTime)
			}
		})
	}
}

func TestEnforcementHistoryRefusesAnInstantAfterTheDatabaseTime(t *testing.T) {
	t.Parallel()
	session := accountSessionManagementScopeSession(t, time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
	transaction := &clockStoreTransaction{}
	store := &DeviceEnforcementHistoryStore{database: clockStoreResourceDatabase{transaction}, options: clockStoreOptions}
	_, err := store.ReadEnforcementHistory(t.Context(), session, testNetworkMemberScope(t),
		clockStoreDatabaseTime.Add(time.Microsecond), node.ID{}, 2)
	if !errors.Is(err, enforcementledger.ErrInvalidRequest) {
		t.Fatalf("ReadEnforcementHistory(after the database time) error = %v", err)
	}
	for _, call := range transaction.calls {
		if call.query == readDeviceEnforcementHistorySQL {
			t.Fatal("an instant after the database time reached PostgreSQL")
		}
	}
	transaction = &clockStoreTransaction{}
	store = &DeviceEnforcementHistoryStore{database: clockStoreResourceDatabase{transaction}, options: clockStoreOptions}
	past := clockStoreDatabaseTime.Add(-time.Hour)
	if _, err := store.ReadEnforcementHistory(t.Context(), session, testNetworkMemberScope(t), past, node.ID{},
		2); !errors.Is(err, enforcementledger.ErrUnavailable) {
		t.Fatalf("ReadEnforcementHistory(past) error = %v", err)
	}
	assertClockStoreArgument(t, "past instant", transaction.call(t, readDeviceEnforcementHistorySQL), 12, past)
}

func TestAuditHistoryDefaultsItsWindowOnTheDatabaseClock(t *testing.T) {
	t.Parallel()
	session := accountSessionManagementScopeSession(t, time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC))
	workspaceID := testNetworkMemberScope(t).WorkspaceID()
	since := clockStoreDatabaseTime.Add(-history.DefaultWindow)
	for _, test := range []struct {
		name  string
		query string
		run   func(*AuditHistoryStore) error
	}{
		{"list", listWorkspaceAuditEventsSQL, func(store *AuditHistoryStore) error {
			_, err := store.List(t.Context(), session, history.Query{WorkspaceID: workspaceID, PageSize: 10})
			return err
		}},
		{"export", exportWorkspaceAuditEventsSQL, func(store *AuditHistoryStore) error {
			_, err := store.ExportChunk(t.Context(), session, history.ExportQuery{WorkspaceID: workspaceID}, nil,
				history.ExportChunkSize)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transaction := &clockStoreTransaction{}
			store := &AuditHistoryStore{database: clockStoreAccountDatabase{transaction}, options: clockStoreOptions}
			if err := test.run(store); err == nil {
				t.Fatal("the recorder ends every unit of work with an error")
			}
			arguments := transaction.call(t, test.query)
			assertClockStoreArgument(t, test.name+" since", arguments, 11, since)
			assertClockStoreArgument(t, test.name+" until", arguments, 12, clockStoreDatabaseTime)
		})
	}
	// A Since after the database's present leaves no window to read.
	transaction := &clockStoreTransaction{}
	store := &AuditHistoryStore{database: clockStoreAccountDatabase{transaction}, options: clockStoreOptions}
	if _, err := store.List(t.Context(), session, history.Query{WorkspaceID: workspaceID, PageSize: 10,
		Since: clockStoreDatabaseTime.Add(time.Second)}); !errors.Is(err, history.ErrInvalid) {
		t.Fatalf("List(since after the database time) error = %v", err)
	}
}
