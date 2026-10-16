package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/ledger"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network/aliasrange"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
)

// databaseClockTestTime is what the fake database clock answers. It is far
// from any host clock, so a store that passes its own time to SQL is caught.
var databaseClockTestTime = time.Date(2001, time.February, 3, 4, 5, 6, 789000, time.UTC)

// errDatabaseClockTestStop ends a store call once the statement under test
// has been recorded.
var errDatabaseClockTestStop = errors.New("database clock test: statement recorded")

type databaseClockStatement struct {
	query     string
	arguments []any
}

// databaseClockRecorder stands in for one PostgreSQL transaction: it answers
// the transaction time and the scope lock, and records every other statement.
type databaseClockRecorder struct {
	statements []databaseClockStatement
	timeReads  int
}

func (recorder *databaseClockRecorder) row(query string, arguments []any) databaseClockRow {
	switch query {
	case transactionTimeSQL:
		recorder.timeReads++
		return databaseClockRow{values: []any{databaseClockTestTime}}
	case setResourceAuthorityScopeSQL:
		return databaseClockRow{values: []any{int64(101), int64(201)}}
	}
	recorder.statements = append(recorder.statements,
		databaseClockStatement{query: query, arguments: append([]any(nil), arguments...)})
	return databaseClockRow{err: errDatabaseClockTestStop}
}

// statement returns the recorded arguments of one statement.
func (recorder *databaseClockRecorder) statement(t *testing.T, query string) []any {
	t.Helper()
	for _, statement := range recorder.statements {
		if statement.query == query {
			return statement.arguments
		}
	}
	t.Fatalf("statement not run; ran %d others", len(recorder.statements))
	return nil
}

type databaseClockRow struct {
	values []any
	err    error
}

func (row databaseClockRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("database clock test: scan arity")
	}
	for index, value := range row.values {
		switch target := destinations[index].(type) {
		case *time.Time:
			*target = value.(time.Time)
		case *int64:
			*target = value.(int64)
		default:
			return errors.New("database clock test: scan type")
		}
	}
	return nil
}

type databaseClockAccountSessionDatabase struct{ recorder *databaseClockRecorder }

func (database databaseClockAccountSessionDatabase) Begin(context.Context) (accountSessionTransaction, error) {
	return databaseClockAccountSessionTransaction(database), nil
}

type databaseClockAccountSessionTransaction struct{ recorder *databaseClockRecorder }

func (databaseClockAccountSessionTransaction) Exec(context.Context, string, ...any) error { return nil }

func (transaction databaseClockAccountSessionTransaction) QueryRow(
	_ context.Context, query string, arguments ...any,
) accountSessionRow {
	return transaction.recorder.row(query, arguments)
}

func (databaseClockAccountSessionTransaction) Commit(context.Context) error   { return nil }
func (databaseClockAccountSessionTransaction) Rollback(context.Context) error { return nil }

type databaseClockResourceAuthorityDatabase struct{ recorder *databaseClockRecorder }

func (database databaseClockResourceAuthorityDatabase) Begin(
	context.Context, bool,
) (resourceAuthorityDatabaseTransaction, error) {
	return databaseClockResourceAuthorityTransaction(database), nil
}

func (database databaseClockResourceAuthorityDatabase) BeginRepeatableRead(
	context.Context,
) (resourceAuthorityDatabaseTransaction, error) {
	return databaseClockResourceAuthorityTransaction(database), nil
}

type databaseClockResourceAuthorityTransaction struct{ recorder *databaseClockRecorder }

func (databaseClockResourceAuthorityTransaction) Exec(context.Context, string, ...any) error {
	return nil
}

func (transaction databaseClockResourceAuthorityTransaction) QueryRow(
	_ context.Context, query string, arguments ...any,
) resourceAuthorityRow {
	return transaction.recorder.row(query, arguments)
}

func (databaseClockResourceAuthorityTransaction) Commit(context.Context) error   { return nil }
func (databaseClockResourceAuthorityTransaction) Rollback(context.Context) error { return nil }

// assertOnlyDatabaseClock checks that the statement ran with a time and that
// every time it was given is the database clock's.
func assertOnlyDatabaseClock(t *testing.T, recorder *databaseClockRecorder, query string) {
	t.Helper()
	if recorder.timeReads != 1 {
		t.Fatalf("database clock read %d times, want once per unit of work", recorder.timeReads)
	}
	timed := false
	for _, argument := range recorder.statement(t, query) {
		if at, ok := argument.(time.Time); ok {
			timed = true
			if !at.Equal(databaseClockTestTime) {
				t.Fatalf("statement got time %s, want the database clock's %s", at, databaseClockTestTime)
			}
		}
	}
	if !timed {
		t.Fatal("statement got no time")
	}
}

func databaseClockTestID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func databaseClockAccountSessionOptions() AccountSessionOptions {
	return AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}
}

func TestGroupTagAndRangeStoresDecideOnTheDatabaseClock(t *testing.T) {
	t.Parallel()
	session := policyApprovalSessionFixture(t, 401, 601)
	scope := postgresPolicySimulationScope(t)
	workspaceID := scope.WorkspaceID()
	correlation := databaseClockTestID(t, "01890f00-0000-7000-8000-000000000901")
	groupID := databaseClockTestID(t, "01890f00-0000-7000-8000-000000000902")
	memberID := databaseClockTestID(t, "01890f00-0000-7000-8000-000000000903")
	deviceID, err := node.ParseID("01890f00-0000-7000-8000-000000000904")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		query string
		call  func(database accountSessionDatabase) error
	}{
		{"device groups list", listDeviceGroupsSQL, func(database accountSessionDatabase) error {
			store := &DeviceGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.List(t.Context(), session, scope)
			return err
		}},
		{"device group members", readDeviceGroupMembersSQL, func(database accountSessionDatabase) error {
			store := &DeviceGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Members(t.Context(), session, scope, devicegroup.ID(groupID), node.ID{}, 10)
			return err
		}},
		{"device group change", changeDeviceGroupSQL, func(database accountSessionDatabase) error {
			store := &DeviceGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Change(t.Context(), devicegroup.Change{Session: session, Scope: scope,
				Operation: devicegroup.OperationDelete, GroupID: devicegroup.ID(groupID), ExpectedVersion: 1,
				CorrelationID: correlation})
			return err
		}},
		{"device group members change", changeDeviceGroupMembersSQL, func(database accountSessionDatabase) error {
			store := &DeviceGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.ChangeMembers(t.Context(), devicegroup.MembershipChange{Session: session, Scope: scope,
				GroupID: devicegroup.ID(groupID), ExpectedVersion: 1, Add: []node.ID{deviceID},
				AddMemberIDs: []publicid.ID{memberID}, CorrelationID: correlation})
			return err
		}},
		{"identity groups list", listIdentityGroupsSQL, func(database accountSessionDatabase) error {
			store := &IdentityGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.List(t.Context(), session, workspaceID)
			return err
		}},
		{"identity group members", readIdentityGroupMembersSQL, func(database accountSessionDatabase) error {
			store := &IdentityGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Members(t.Context(), session, workspaceID, identitygroup.ID(groupID), publicid.ID{}, 10)
			return err
		}},
		{"identity group change", changeIdentityGroupSQL, func(database accountSessionDatabase) error {
			store := &IdentityGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Change(t.Context(), identitygroup.Change{Session: session, WorkspaceID: workspaceID,
				Operation: identitygroup.OperationDelete, GroupID: identitygroup.ID(groupID), ExpectedVersion: 1,
				CorrelationID: correlation})
			return err
		}},
		{"identity group members change", changeIdentityGroupMembersSQL, func(database accountSessionDatabase) error {
			store := &IdentityGroupStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.ChangeMembers(t.Context(), identitygroup.MembershipChange{Session: session,
				WorkspaceID: workspaceID, GroupID: identitygroup.ID(groupID), ExpectedVersion: 1,
				Add: []publicid.ID{memberID}, AddMemberIDs: []publicid.ID{correlation}, CorrelationID: correlation})
			return err
		}},
		{"device tags list", listDeviceTagsSQL, func(database accountSessionDatabase) error {
			store := &DeviceTagStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.List(t.Context(), session, workspaceID)
			return err
		}},
		{"device tag change", changeDeviceTagSQL, func(database accountSessionDatabase) error {
			store := &DeviceTagStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Change(t.Context(), devicetag.Change{Session: session, WorkspaceID: workspaceID,
				Operation: devicetag.OperationDelete, TagID: devicetag.ID(groupID), ExpectedVersion: 1,
				CorrelationID: correlation})
			return err
		}},
		{"network device tags", readNetworkDeviceTagsSQL, func(database accountSessionDatabase) error {
			store := &DeviceTagStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.NetworkTags(t.Context(), session, scope)
			return err
		}},
		{"network tag options", readNetworkTagOptionsSQL, func(database accountSessionDatabase) error {
			store := &DeviceTagStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.NetworkOptions(t.Context(), session, scope)
			return err
		}},
		{"device tag assignments", changeDeviceTagsSQL, func(database accountSessionDatabase) error {
			store := &DeviceTagStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.ChangeAssignments(t.Context(), devicetag.AssignmentChange{Session: session, Scope: scope,
				DeviceID: deviceID, Add: []devicetag.ID{devicetag.ID(groupID)},
				AddAssignmentIDs: []publicid.ID{memberID}, CorrelationID: correlation})
			return err
		}},
		{"alias ranges read", readNetworkAliasRangesSQL, func(database accountSessionDatabase) error {
			store := &NetworkAliasRangeStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Read(t.Context(), session, scope)
			return err
		}},
		{"alias ranges update", setNetworkAliasRangesSQL, func(database accountSessionDatabase) error {
			store := &NetworkAliasRangeStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Update(t.Context(), aliasrange.Command{Session: session, Scope: scope,
				ExpectedVersion: 1, IPv4: aliasrange.Change{Present: true}, CorrelationID: correlation})
			return err
		}},
		{"address usage read", readNetworkAddressUsageSQL, func(database accountSessionDatabase) error {
			store := &NetworkAddressUsageStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.Read(t.Context(), session, scope)
			return err
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			recorder := &databaseClockRecorder{}
			if err := test.call(databaseClockAccountSessionDatabase{recorder: recorder}); err == nil {
				t.Fatal("store ignored the recorded statement's failure")
			}
			assertOnlyDatabaseClock(t, recorder, test.query)
		})
	}
}

func TestPolicyReadStoresAuthorizeOnTheDatabaseClock(t *testing.T) {
	t.Parallel()
	session := policyApprovalSessionFixture(t, 401, 601)
	scope := postgresPolicySimulationScope(t)
	source, err := node.ParseID("01890f00-0000-7000-8000-000000000911")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := node.ParseID("01890f00-0000-7000-8000-000000000912")
	if err != nil {
		t.Fatal(err)
	}
	explain, err := accessgraph.NewQuery(accessgraph.QueryParams{Scope: scope, SourceNodeID: source,
		DestinationNodeID: destination, Protocol: policy.ProtocolTCP, DestinationPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := accessgraph.NewGraphQuery(accessgraph.GraphQueryParams{Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	options := AccessGraphOptions{StatementTimeout: time.Second, LockTimeout: time.Second, IdleTimeout: time.Second}
	cases := []struct {
		name  string
		query string
		call  func(database resourceAuthorityDatabase) error
	}{
		{"explain", explainActivePolicySQL, func(database resourceAuthorityDatabase) error {
			_, err := (&AccessGraphStore{database: database, options: options}).ReadActive(t.Context(), session, explain)
			return err
		}},
		{"graph", readAccessGraphSQL, func(database resourceAuthorityDatabase) error {
			_, err := (&AccessGraphStore{database: database, options: options}).ReadGraph(t.Context(), session, graph)
			return err
		}},
		{"simulation baseline", readPolicySimulationBaselineSQL, func(database resourceAuthorityDatabase) error {
			store := &PolicySimulationStore{database: database, options: PolicySimulationOptions(options)}
			_, err := store.ReadSimulationBaseline(t.Context(), session, scope)
			return err
		}},
		{"active policy", readActivePolicySQL, func(database resourceAuthorityDatabase) error {
			store := &ActivePolicyStore{database: database, options: PolicySimulationOptions(options)}
			_, err := store.ReadActivePolicy(t.Context(), session, scope)
			return err
		}},
		{"history at present", readAccessGraphHistorySQL, func(database resourceAuthorityDatabase) error {
			store := &AccessGraphHistoryStore{database: database, options: databaseClockAccountSessionOptions()}
			_, err := store.ReadHistory(t.Context(), session, scope, ledger.Query{Limit: 2})
			return err
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			recorder := &databaseClockRecorder{}
			if err := test.call(databaseClockResourceAuthorityDatabase{recorder: recorder}); err == nil {
				t.Fatal("store ignored the recorded statement's failure")
			}
			assertOnlyDatabaseClock(t, recorder, test.query)
		})
	}
}

func TestAccessGraphHistoryStoreReadsAPastInstantOnTheDatabaseClock(t *testing.T) {
	t.Parallel()
	recorder := &databaseClockRecorder{}
	store := &AccessGraphHistoryStore{database: databaseClockResourceAuthorityDatabase{recorder: recorder},
		options: databaseClockAccountSessionOptions()}
	past := databaseClockTestTime.Add(-time.Hour)
	if _, err := store.ReadHistory(t.Context(), policyApprovalSessionFixture(t, 401, 601),
		postgresPolicySimulationScope(t), ledger.Query{At: past, Limit: 2}); err == nil {
		t.Fatal("store ignored the recorded statement's failure")
	}
	arguments := recorder.statement(t, readAccessGraphHistorySQL)
	// $12 is the evaluation time and $13 the instant read.
	if evaluated, ok := arguments[11].(time.Time); !ok || !evaluated.Equal(databaseClockTestTime) {
		t.Fatalf("evaluated at %v, want the database clock's %s", arguments[11], databaseClockTestTime)
	}
	if at, ok := arguments[12].(time.Time); !ok || !at.Equal(past) {
		t.Fatalf("read at %v, want %s", arguments[12], past)
	}
}
