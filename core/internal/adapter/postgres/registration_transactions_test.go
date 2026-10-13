package postgres

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/enrollment/registration"
)

func TestRegistrationTransactionCreatesCompleteAtomicMutation(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	database := newFakeRegistrationDatabaseTransaction()
	enqueueOpenRegistrationResolution(t, database, command)
	enqueueRegistrationWrites(database)
	transaction := beginTestRegistrationTransaction(t, database, command)

	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change := testRegistrationChange(t, command, resolution)
	result, err := transaction.Apply(t.Context(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.NodeID() != change.NodeID() || result.Hostname().String() != "node-one-1.example" ||
		result.Disposition() != registration.DispositionCreated || result.NetworkRevision() != 8 {
		t.Fatalf("Apply() result = %+v, want created Node with allocated name and revision", result)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if database.commitCalls != 1 || database.rollbackCalls != 0 {
		t.Fatalf("database lifecycle = commit %d rollback %d, want 1/0", database.commitCalls, database.rollbackCalls)
	}
	if got := database.calls[0].arguments; !reflect.DeepEqual(
		got,
		[]any{"5000ms", "1000ms", "10000ms"},
	) {
		t.Fatalf("transaction timeout arguments = %#v", got)
	}
	if got := database.calls[1].arguments; !reflect.DeepEqual(
		got,
		[]any{command.Scope.WorkspaceID().String(), command.Scope.NetworkID().String()},
	) {
		t.Fatalf("transaction scope arguments = %#v", got)
	}

	wantCalls := []string{
		configureRegistrationTransactionSQL,
		setRegistrationTransactionScopeSQL,
		lockPendingRegistrationSQL,
		lockRegistrationNetworkRevisionSQL,
		lockRegistrationEnrollmentAuthoritySQL,
		lockRegistrationProfileSQL,
		lockRegistrationDeviceSQL,
		lockRegistrationAuditStreamSQL,
		registrationHostnamesTakenSQL,
		registrationHostnamesTakenSQL,
		lockRegistrationPrefixesSQL,
		lockRegistrationAddressFloorSQL,
		loadRegistrationLeasesSQL,
		setRegistrationChangeSQL,
		insertRegistrationDeviceSQL,
		insertRegistrationMachineKeySQL,
		insertRegistrationNodeKeySQL,
		consumeRegistrationEnrollmentAuthoritySQL,
		insertRegistrationCredentialUseSQL,
		releaseReclaimedRegistrationLeaseSQL,
		insertRegistrationLeaseSQL,
		storeRegistrationAddressFloorSQL,
		advanceRegistrationRevisionSQL,
		completePendingRegistrationSQL,
		appendRegistrationEvidenceSQL,
	}
	if got := registrationCallQueries(database.calls); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("database call order mismatch\ngot:  %#v\nwant: %#v", got, wantCalls)
	}
	hostnameCall := findRegistrationCall(t, database.calls, registrationHostnamesTakenSQL)
	if len(hostnameCall.arguments) != 4 ||
		!reflect.DeepEqual(hostnameCall.arguments[2], []string{command.Hostname.String()}) ||
		hostnameCall.arguments[3] != nil {
		t.Fatalf("hostname arguments = %#v, want the requested hostname alone first", hostnameCall.arguments)
	}
	floorCall := findRegistrationCall(t, database.calls, storeRegistrationAddressFloorSQL)
	if !reflect.DeepEqual(floorCall.arguments, []any{int64(501), "100.64.1.2/32", "100.64.1.0/24"}) {
		t.Fatalf("floor arguments = %#v, want the address after the lease", floorCall.arguments)
	}
	leaseCall := findRegistrationCall(t, database.calls, insertRegistrationLeaseSQL)
	if len(leaseCall.arguments) != 10 || leaseCall.arguments[7] != "100.64.1.1" ||
		leaseCall.arguments[8] != 4 {
		t.Fatalf("lease arguments = %#v, want deterministic IPv4 candidate", leaseCall.arguments)
	}
	evidenceCall := findRegistrationCall(t, database.calls, appendRegistrationEvidenceSQL)
	if len(evidenceCall.arguments) != 15 || evidenceCall.arguments[8] != int64(8) ||
		evidenceCall.arguments[10] != "device.registered" {
		t.Fatalf("evidence arguments = %#v, want revision-bound audit/outbox", evidenceCall.arguments)
	}
}

func TestRegistrationTransactionResumesWithoutReplacingKeysOrLeases(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	database := newFakeRegistrationDatabaseTransaction()
	enqueueOpenRegistrationResolution(t, database, command)
	machineKey := command.Identity.MachineKey().Bytes()
	nodeKey := command.Identity.NodeKey().Bytes()
	database.rows[lockRegistrationDeviceSQL][0] = registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 603
		*destinations[1].(*string) = testRegistrationNodePublicID
		*destinations[2].(*int64) = 601
		*destinations[3].(*string) = "old-node.example"
		*destinations[4].(*int64) = 5
		*destinations[5].(*[]byte) = append([]byte(nil), machineKey[:]...)
		*destinations[6].(*[]byte) = append([]byte(nil), nodeKey[:]...)
		return nil
	}}
	database.enqueueRows(lockRegistrationDeviceLeasesSQL, &registrationTestRows{scans: []func(...any) error{
		func(destinations ...any) error {
			*destinations[0].(*int) = 4
			return nil
		},
	}})
	database.enqueueRow(resumeRegistrationDeviceSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 6
		return nil
	}})
	database.enqueueRow(advanceRegistrationRevisionSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 8
		*destinations[1].(*int64) = 6
		return nil
	}})
	database.enqueueRow(appendRegistrationEvidenceSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 3
		return nil
	}})
	transaction := beginTestRegistrationTransaction(t, database, command)

	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if existingNode, exists := resolution.ExistingNodeID(); !exists ||
		existingNode.String() != testRegistrationNodePublicID {
		t.Fatalf("ExistingNodeID() = (%v, %t), want resumable Node", existingNode, exists)
	}
	change := testRegistrationChangeWithDisposition(
		t,
		command,
		resolution,
		registration.DispositionResumed,
	)
	result, err := transaction.Apply(t.Context(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Disposition() != registration.DispositionResumed || result.NodeID() != change.NodeID() {
		t.Fatalf("Apply() result = %+v, want resumed existing Node", result)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	for _, forbidden := range []string{
		insertRegistrationDeviceSQL,
		insertRegistrationMachineKeySQL,
		insertRegistrationNodeKeySQL,
		insertRegistrationLeaseSQL,
		// The Device keeps its IPv4 lease, so no prefix is examined.
		lockRegistrationAddressFloorSQL,
		storeRegistrationAddressFloorSQL,
	} {
		for _, call := range database.calls {
			if call.query == forbidden {
				t.Fatalf("resume replaced stable registration resource with query %q", forbidden)
			}
		}
	}
	evidenceCall := findRegistrationCall(t, database.calls, appendRegistrationEvidenceSQL)
	if evidenceCall.arguments[10] != "device.resumed" {
		t.Fatalf("resume audit action = %#v, want device.resumed", evidenceCall.arguments[10])
	}
}

func TestRegistrationTransactionReturnsCompletedIntentWithoutMutation(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	database := newFakeRegistrationDatabaseTransaction()
	enqueueOpenRegistrationResolution(t, database, command)
	pending := database.rows[lockPendingRegistrationSQL][0].(registrationTestRow)
	originalScan := pending.scan
	pending.scan = func(destinations ...any) error {
		if err := originalScan(destinations...); err != nil {
			return err
		}
		*destinations[7].(*sql.NullInt64) = sql.NullInt64{Int64: 603, Valid: true}
		*destinations[8].(*sql.NullString) = sql.NullString{String: "node-one.example", Valid: true}
		*destinations[9].(*sql.NullString) = sql.NullString{String: "created", Valid: true}
		*destinations[10].(*sql.NullInt64) = sql.NullInt64{Int64: 7, Valid: true}
		*destinations[11].(*string) = "completed"
		return nil
	}
	database.rows[lockPendingRegistrationSQL][0] = pending
	database.enqueueRow(lockCompletedRegistrationDeviceSQL, registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = testRegistrationNodePublicID
		return nil
	}})
	transaction := beginTestRegistrationTransaction(t, database, command)

	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	result, completed := resolution.CompletedResult()
	if !completed || result.NodeID().String() != testRegistrationNodePublicID ||
		result.NetworkRevision() != 7 {
		t.Fatalf("CompletedResult() = (%+v, %t), want original completion", result, completed)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	for _, call := range database.calls {
		if call.query == lockRegistrationAuditStreamSQL || call.query == setRegistrationChangeSQL {
			t.Fatalf("completed intent reached allocation or mutation query %q", call.query)
		}
	}
}

func TestRegistrationTransactionRejectsConflictingIntentBeforeMutation(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	database := newFakeRegistrationDatabaseTransaction()
	enqueueOpenRegistrationResolution(t, database, command)
	row := database.rows[lockPendingRegistrationSQL][0].(registrationTestRow)
	originalScan := row.scan
	row.scan = func(destinations ...any) error {
		if err := originalScan(destinations...); err != nil {
			return err
		}
		requestHash := *destinations[4].(*[]byte)
		requestHash[0] ^= 0xff
		return nil
	}
	database.rows[lockPendingRegistrationSQL][0] = row
	transaction := beginTestRegistrationTransaction(t, database, command)

	_, err := transaction.Resolve(t.Context(), command)
	if !errors.Is(err, registration.ErrIntentConflict) ||
		!errors.Is(err, ErrResolveRegistrationTransaction) {
		t.Fatalf("Resolve() error = %v, want classified intent conflict", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if database.commitCalls != 0 || database.rollbackCalls != 1 {
		t.Fatalf("database lifecycle = commit %d rollback %d, want 0/1", database.commitCalls, database.rollbackCalls)
	}
	for _, call := range database.calls {
		if call.query == setRegistrationChangeSQL {
			t.Fatal("conflicting intent reached mutation phase")
		}
	}
}

func TestRegistrationTransactionLifecycleIsJoinedAndIdempotent(t *testing.T) {
	t.Parallel()

	database := newFakeRegistrationDatabaseTransaction()
	transaction := &registrationTransaction{
		database: database,
		state:    registrationTransactionOpen,
	}
	const callers = 32
	var waitGroup sync.WaitGroup
	errorsByCaller := make(chan error, callers)
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errorsByCaller <- transaction.Rollback(t.Context())
		}()
	}
	waitGroup.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Fatalf("concurrent Rollback() error = %v", err)
		}
	}
	if database.rollbackCalls != 1 || database.commitCalls != 0 {
		t.Fatalf("database lifecycle = commit %d rollback %d, want exactly one rollback", database.commitCalls, database.rollbackCalls)
	}
}

func TestRegistrationTransactionsValidateOptionsAndPoolRole(t *testing.T) {
	t.Parallel()

	database := &fakeRegistrationTransactionDatabase{}
	if _, err := NewRegistrationTransactions(&Pool{
		role:                            PoolRoleWorker,
		registrationTransactionDatabase: database,
	}, testRegistrationTransactionOptions()); !errors.Is(err, ErrInvalidRegistrationTransactions) {
		t.Fatalf("NewRegistrationTransactions(worker) error = %v", err)
	}
	if _, err := NewRegistrationTransactions(&Pool{
		role:                            PoolRoleRuntime,
		registrationTransactionDatabase: database,
	}, testRegistrationTransactionOptions()); err != nil {
		t.Fatalf("NewRegistrationTransactions(runtime) error = %v", err)
	}
	invalid := testRegistrationTransactionOptions()
	invalid.AddressCandidateLimit = 0
	if _, err := newRegistrationTransactions(database, invalid, nil); !errors.Is(err, ErrInvalidRegistrationTransactions) {
		t.Fatalf("newRegistrationTransactions(invalid options) error = %v", err)
	}
}

func TestRegistrationDatabaseErrorsPreserveRetryAndCommitSemantics(t *testing.T) {
	t.Parallel()

	retryable := classifyRegistrationDatabaseError(t.Context(), &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "node_address_lease_address_live_uidx",
	})
	if !errors.Is(retryable, registration.ErrRetryableTransaction) {
		t.Fatalf("classifyRegistrationDatabaseError() = %v, want retryable collision", retryable)
	}
	unknown := errors.New("connection lost after COMMIT")
	classified := classifyRegistrationCommitError(t.Context(), unknown)
	if !errors.Is(classified, registration.ErrCommitOutcomeUnknown) || !errors.Is(classified, unknown) {
		t.Fatalf("classifyRegistrationCommitError() = %v, want uncertain durable outcome", classified)
	}
	canceledContext, cancel := context.WithCancel(t.Context())
	cancel()
	classified = classifyRegistrationCommitError(canceledContext, unknown)
	if !errors.Is(classified, context.Canceled) ||
		!errors.Is(classified, registration.ErrCommitOutcomeUnknown) {
		t.Fatalf("classifyRegistrationCommitError(canceled) = %v", classified)
	}
}
