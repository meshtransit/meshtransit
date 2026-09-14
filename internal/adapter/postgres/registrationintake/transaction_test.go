package registrationintake

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	appintake "github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

func TestTransactionCreatesPendingIntentWithAuditAndOutbox(t *testing.T) {
	t.Parallel()

	lookup := validLookup(t)
	databaseTransaction := newFakeDatabaseTransaction()
	enqueueBegin(t, databaseTransaction, lookup)
	enqueueOpenResolution(t, databaseTransaction, lookup)
	enqueueApply(databaseTransaction)
	transactions := newTestTransactions(t, databaseTransaction)

	value, err := transactions.Begin(t.Context(), lookup)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction, ok := value.(*transaction)
	if !ok {
		t.Fatalf("Begin() type = %T, want *transaction", value)
	}
	resolution, err := transaction.Resolve(t.Context(), lookup)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change := validChange(t, resolution.Authority(), lookup)
	if err := transaction.Apply(t.Context(), change); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	wantQueries := []string{
		configureTransactionSQL,
		resolveScopeSQL,
		setScopeSQL,
		lockIntentsSQL,
		lockRevisionSQL,
		lockEnrollmentAuthoritySQL,
		loadDigestSQL,
		lockProfileSQL,
		lockAuditHeadSQL,
		setChangeIDSQL,
		insertIntentSQL,
		appendEvidenceSQL,
	}
	if got := callQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("database call order mismatch\ngot:  %#v\nwant: %#v", got, wantQueries)
	}
	if databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf(
			"database lifecycle = commit %d rollback %d, want 1/0",
			databaseTransaction.commitCalls,
			databaseTransaction.rollbackCalls,
		)
	}
	scopeCall := findCall(t, databaseTransaction.calls, resolveScopeSQL)
	if !reflect.DeepEqual(scopeCall.arguments, []any{lookup.CredentialID.String()}) {
		t.Fatalf("scope resolution arguments = %#v, want credential public ID only", scopeCall.arguments)
	}
	insert := findCall(t, databaseTransaction.calls, insertIntentSQL)
	if len(insert.arguments) != 12 || insert.arguments[0] != lookup.RegistrationID.String() ||
		insert.arguments[4] != "credential" || insert.arguments[10] == nil {
		t.Fatalf("pending-intent insert arguments = %#v", insert.arguments)
	}
	evidence := findCall(t, databaseTransaction.calls, appendEvidenceSQL)
	if len(evidence.arguments) != 18 || evidence.arguments[6] != "pending_registration" ||
		evidence.arguments[11] != "registration.requested" || evidence.arguments[12] != "device.register" {
		t.Fatalf("audit/outbox evidence arguments = %#v", evidence.arguments)
	}
}

func TestNewTransactionsRejectsNilPool(t *testing.T) {
	t.Parallel()

	if _, err := NewTransactions(nil, testOptions()); !errors.Is(err, ErrInvalidTransactions) {
		t.Fatalf("NewTransactions() error = %v, want invalid transactions", err)
	}
}

func TestTransactionReturnsCanonicalExistingIntentWithoutWrite(t *testing.T) {
	t.Parallel()

	lookup := validLookup(t)
	databaseTransaction := newFakeDatabaseTransaction()
	enqueueBegin(t, databaseTransaction, lookup)
	enqueueOpenResolution(t, databaseTransaction, lookup)
	canonicalID := mustRegistrationID(t, "01890f60-0000-7000-8000-000000000099")
	authority := expectedAuthority(t)
	command := validCommand(t, authority, canonicalID)
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	databaseTransaction.rowSets[lockIntentsSQL] = []databaseRows{intentRows(
		t,
		canonicalID,
		701,
		hash,
		lookup.MachineFingerprint,
		command,
	)}
	transaction := beginTestTransaction(t, databaseTransaction, lookup)

	resolution, err := transaction.Resolve(t.Context(), lookup)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	gotID, gotHash, exists := resolution.ExistingIntent()
	if !exists || gotID != canonicalID || gotHash != hash {
		t.Fatalf("ExistingIntent() = (%v, %v, %t), want canonical durable intent", gotID, gotHash, exists)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	for _, call := range databaseTransaction.calls {
		if call.query == lockAuditHeadSQL || call.query == insertIntentSQL || call.query == appendEvidenceSQL {
			t.Fatalf("replay reached mutation query %q", call.query)
		}
	}
}

func TestTransactionRejectsMalformedDigestEvidence(t *testing.T) {
	t.Parallel()

	lookup := validLookup(t)
	databaseTransaction := newFakeDatabaseTransaction()
	enqueueBegin(t, databaseTransaction, lookup)
	enqueueOpenResolution(t, databaseTransaction, lookup)
	databaseTransaction.rows[loadDigestSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = "unknown"
		*destinations[1].(*string) = "test-key-v1"
		*destinations[2].(*[]byte) = make([]byte, 32)
		*destinations[3].(*[]byte) = make([]byte, 16)
		return nil
	}}}
	transaction := beginTestTransaction(t, databaseTransaction, lookup)

	_, err := transaction.Resolve(t.Context(), lookup)
	if !errors.Is(err, ErrEvidence) {
		t.Fatalf("Resolve() error = %v, want invalid evidence", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestTransactionClassifiesCredentialAndRetryableFailures(t *testing.T) {
	t.Parallel()

	for _, databaseError := range []error{postgresError("23503", ""), pgx.ErrNoRows} {
		credentialFailure := classifyDatabaseError(t.Context(), databaseError)
		if !errors.Is(credentialFailure, appintake.ErrCredentialRejected) {
			t.Fatalf("credential error = %v, want non-oracular rejection", credentialFailure)
		}
	}
	retryable := classifyDatabaseError(
		t.Context(),
		postgresError("23505", "pending_registration_machine_active_uidx"),
	)
	if !errors.Is(retryable, appintake.ErrRetryableTransaction) {
		t.Fatalf("unique active-machine error = %v, want whole-transaction retry", retryable)
	}
}

func TestResolvePreparedVerifiesDurableSemanticEvidence(t *testing.T) {
	t.Parallel()

	authority := expectedAuthority(t)
	command := validCommand(t, authority, mustRegistrationID(t, testIntentID))
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	databaseTransaction := newFakeDatabaseTransaction()
	databaseTransaction.rows[setScopeSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 101
		*destinations[1].(*int64) = 201
		return nil
	}}}
	machineFingerprint := command.Identity.MachineKey().Fingerprint()
	nodeKey := command.Identity.NodeKey().Bytes()
	databaseTransaction.rows[loadPreparedIntentSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*[]byte) = append([]byte(nil), hash[:]...)
		*destinations[1].(*string) = command.CredentialID.String()
		*destinations[2].(*[]byte) = append([]byte(nil), machineFingerprint[:]...)
		*destinations[3].(*[]byte) = append([]byte(nil), nodeKey[:]...)
		*destinations[4].(*int16) = 2
		*destinations[5].(*string) = "pending"
		*destinations[6].(*int64) = 1
		return nil
	}}}
	transactions := newTestTransactions(t, databaseTransaction)

	got, found, err := transactions.ResolvePrepared(t.Context(), command)
	if err != nil {
		t.Fatalf("ResolvePrepared() error = %v", err)
	}
	if !found || got != hash {
		t.Fatalf("ResolvePrepared() = (%v, %t), want exact durable hash", got, found)
	}
	wantQueries := []string{configureTransactionSQL, setScopeSQL, loadPreparedIntentSQL}
	if gotQueries := callQueries(databaseTransaction.calls); !reflect.DeepEqual(gotQueries, wantQueries) {
		t.Fatalf("resolver queries = %#v, want %#v", gotQueries, wantQueries)
	}
	if databaseTransaction.rollbackCalls != 1 || databaseTransaction.commitCalls != 0 {
		t.Fatalf(
			"resolver lifecycle = rollback %d commit %d, want 1/0",
			databaseTransaction.rollbackCalls,
			databaseTransaction.commitCalls,
		)
	}
}

func TestTransactionRollbackIsConcurrentSafeAndIdempotent(t *testing.T) {
	t.Parallel()

	databaseTransaction := newFakeDatabaseTransaction()
	transaction := &transaction{database: databaseTransaction, state: transactionOpen}
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
			t.Fatalf("Rollback() error = %v", err)
		}
	}
	if databaseTransaction.rollbackCalls != 1 || databaseTransaction.commitCalls != 0 {
		t.Fatalf(
			"database lifecycle = rollback %d commit %d, want 1/0",
			databaseTransaction.rollbackCalls,
			databaseTransaction.commitCalls,
		)
	}
}
