package registrationintake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	appintake "github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	testDeploymentID = "01890f60-0000-7000-8000-000000000001"
	testWorkspaceID  = "01890f60-0000-7000-8000-000000000002"
	testNetworkID    = "01890f60-0000-7000-8000-000000000003"
	testCredentialID = "01890f60-0000-7000-8000-000000000004"
	testProfileID    = "01890f60-0000-7000-8000-000000000005"
	testIssuerID     = "01890f60-0000-7000-8000-000000000006"
	testIntentID     = "01890f60-0000-7000-8000-000000000007"
)

var testNow = time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)

type fakeDatabase struct {
	transactions []*fakeDatabaseTransaction
	next         int
}

func (database *fakeDatabase) Begin(context.Context) (databaseTransaction, error) {
	if database.next >= len(database.transactions) {
		return nil, errors.New("unexpected transaction")
	}
	transaction := database.transactions[database.next]
	database.next++
	return transaction, nil
}

type testCall struct {
	query     string
	arguments []any
}

type fakeDatabaseTransaction struct {
	mu sync.Mutex

	rows          map[string][]databaseRow
	rowSets       map[string][]databaseRows
	execResults   map[string][]commandResult
	calls         []testCall
	commitErr     error
	rollbackErr   error
	commitCalls   int
	rollbackCalls int
}

func newFakeDatabaseTransaction() *fakeDatabaseTransaction {
	return &fakeDatabaseTransaction{
		rows:        make(map[string][]databaseRow),
		rowSets:     make(map[string][]databaseRows),
		execResults: make(map[string][]commandResult),
	}
}

func (transaction *fakeDatabaseTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) (commandResult, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.record(query, arguments)
	queued := transaction.execResults[query]
	if len(queued) == 0 {
		return affectedRows(1), nil
	}
	transaction.execResults[query] = queued[1:]
	return queued[0], nil
}

func (transaction *fakeDatabaseTransaction) Query(
	_ context.Context,
	query string,
	arguments ...any,
) (databaseRows, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.record(query, arguments)
	queued := transaction.rowSets[query]
	if len(queued) == 0 {
		return nil, fmt.Errorf("unexpected rows query: %s", query)
	}
	transaction.rowSets[query] = queued[1:]
	return queued[0], nil
}

func (transaction *fakeDatabaseTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) databaseRow {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.record(query, arguments)
	queued := transaction.rows[query]
	if len(queued) == 0 {
		return testRow{err: fmt.Errorf("unexpected row query: %s", query)}
	}
	transaction.rows[query] = queued[1:]
	return queued[0]
}

func (transaction *fakeDatabaseTransaction) Commit(context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakeDatabaseTransaction) Rollback(context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakeDatabaseTransaction) record(query string, arguments []any) {
	transaction.calls = append(transaction.calls, testCall{
		query:     query,
		arguments: append([]any(nil), arguments...),
	})
}

type affectedRows int64

func (result affectedRows) RowsAffected() int64 { return int64(result) }

type testRow struct {
	scan func(...any) error
	err  error
}

func (row testRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	return row.scan(destinations...)
}

type testRows struct {
	scans  []func(...any) error
	next   int
	closed bool
}

func (rows *testRows) Next() bool { return !rows.closed && rows.next < len(rows.scans) }

func (rows *testRows) Scan(destinations ...any) error {
	scan := rows.scans[rows.next]
	rows.next++
	return scan(destinations...)
}

func (*testRows) Err() error { return nil }

func (rows *testRows) Close() { rows.closed = true }

func testOptions() Options {
	return Options{
		StatementTimeout: 5 * time.Second,
		LockTimeout:      time.Second,
		IdleTimeout:      10 * time.Second,
	}
}

func newTestTransactions(t *testing.T, transaction *fakeDatabaseTransaction) *Transactions {
	t.Helper()
	transactions, err := newTransactions(
		&fakeDatabase{transactions: []*fakeDatabaseTransaction{transaction}},
		testOptions(),
	)
	if err != nil {
		t.Fatalf("NewTransactions() error = %v", err)
	}
	return transactions
}

func beginTestTransaction(
	t *testing.T,
	databaseTransaction *fakeDatabaseTransaction,
	lookup appintake.Lookup,
) *transaction {
	t.Helper()
	transactions := newTestTransactions(t, databaseTransaction)
	value, err := transactions.Begin(t.Context(), lookup)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	result, ok := value.(*transaction)
	if !ok {
		t.Fatalf("Begin() type = %T, want *transaction", value)
	}
	return result
}

func enqueueBegin(
	t *testing.T,
	transaction *fakeDatabaseTransaction,
	lookup appintake.Lookup,
) {
	t.Helper()
	transaction.rows[resolveScopeSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = testDeploymentID
		*destinations[1].(*string) = testWorkspaceID
		*destinations[2].(*string) = testNetworkID
		*destinations[3].(*int64) = 7
		return nil
	}}}
	transaction.rows[setScopeSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 101
		*destinations[1].(*int64) = 201
		return nil
	}}}
	_ = lookup
}

func enqueueOpenResolution(
	t *testing.T,
	transaction *fakeDatabaseTransaction,
	lookup appintake.Lookup,
) {
	t.Helper()
	transaction.rowSets[lockIntentsSQL] = []databaseRows{&testRows{scans: []func(...any) error{}}}
	transaction.rows[lockRevisionSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		for index, value := range [...]int64{7, 5, 2, 3, 4, 5, 6, 1} {
			*destinations[index].(*int64) = value
		}
		return nil
	}}}
	transaction.rows[lockEnrollmentAuthoritySQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 701
		*destinations[1].(*int64) = 601
		*destinations[2].(*int64) = 11
		*destinations[3].(*string) = testIssuerID
		*destinations[4].(*string) = "active"
		*destinations[5].(*string) = "bounded"
		*destinations[6].(*sql.NullInt64) = sql.NullInt64{Int64: 5, Valid: true}
		*destinations[7].(*int64) = 0
		*destinations[8].(*int64) = 7
		*destinations[9].(*time.Time) = testNow.Add(-time.Hour)
		*destinations[10].(*time.Time) = testNow.Add(time.Hour)
		*destinations[11].(*int64) = 3
		return nil
	}}}
	digest := testDigest(t)
	digestBytes := digest.Bytes()
	fingerprint := digest.Fingerprint()
	transaction.rows[loadDigestSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = enrollment.DigestAlgorithmHMACSHA256
		*destinations[1].(*string) = digest.KeyID().String()
		*destinations[2].(*[]byte) = append([]byte(nil), digestBytes[:]...)
		*destinations[3].(*[]byte) = append([]byte(nil), fingerprint[:]...)
		return nil
	}}}
	transaction.rows[lockProfileSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 601
		*destinations[1].(*string) = testProfileID
		*destinations[2].(*int64) = 3600
		*destinations[3].(*string) = "persistent"
		*destinations[4].(*string) = "bounded"
		*destinations[5].(*sql.NullInt64) = sql.NullInt64{Int64: 5, Valid: true}
		*destinations[6].(*string) = "active"
		*destinations[7].(*int64) = 2
		return nil
	}}}
	_ = lookup
}

func enqueueApply(transaction *fakeDatabaseTransaction) {
	transaction.rows[lockAuditHeadSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 301
		*destinations[1].(*int64) = 4
		*destinations[2].(*[]byte) = make([]byte, 32)
		return nil
	}}}
	transaction.rows[insertIntentSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 801
		*destinations[1].(*int64) = 1
		return nil
	}}}
	transaction.rows[appendEvidenceSQL] = []databaseRow{testRow{scan: func(destinations ...any) error {
		*destinations[0].(*int64) = 4
		return nil
	}}}
}

func intentRows(
	t *testing.T,
	registrationID enrollment.RegistrationID,
	credentialInternalID int64,
	hash registration.RequestHash,
	machineFingerprint [32]byte,
	command registration.Command,
) databaseRows {
	t.Helper()
	nodeKey := command.Identity.NodeKey().Bytes()
	return &testRows{scans: []func(...any) error{func(destinations ...any) error {
		*destinations[0].(*int64) = 801
		*destinations[1].(*string) = registrationID.String()
		*destinations[2].(*sql.NullInt64) = sql.NullInt64{Int64: credentialInternalID, Valid: true}
		*destinations[3].(*int16) = 2
		*destinations[4].(*[]byte) = append([]byte(nil), hash[:]...)
		*destinations[5].(*[]byte) = append([]byte(nil), machineFingerprint[:]...)
		*destinations[6].(*[]byte) = append([]byte(nil), nodeKey[:]...)
		*destinations[7].(*string) = "pending"
		*destinations[8].(*int64) = 1
		return nil
	}}}
}

func validLookup(t *testing.T) appintake.Lookup {
	t.Helper()
	identityValue := validIdentity(t)
	return appintake.Lookup{
		RegistrationID:     mustRegistrationID(t, testIntentID),
		CredentialID:       mustCredentialID(t, testCredentialID),
		MachineFingerprint: identityValue.MachineKey().Fingerprint(),
		RequestedNodeKey:   identityValue.NodeKey().Bytes(),
	}
}

func expectedAuthority(t *testing.T) appintake.Authority {
	t.Helper()
	scope := mustScope(t)
	useLimit, err := enrollment.NewBoundedUseLimit(5)
	if err != nil {
		t.Fatalf("NewBoundedUseLimit() error = %v", err)
	}
	profile, err := enrollment.NewProfile(enrollment.ProfileParams{
		ID:                 mustProfileID(t, testProfileID),
		Scope:              scope,
		State:              enrollment.ProfileStateActive,
		NodeLifetime:       time.Hour,
		EphemeralMode:      enrollment.EphemeralModePersistent,
		CredentialUseLimit: useLimit,
	})
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	issuer, err := identity.ParsePrincipalID(testIssuerID)
	if err != nil {
		t.Fatalf("ParsePrincipalID() error = %v", err)
	}
	credential, err := enrollment.NewCredential(enrollment.CredentialParams{
		ID:                  mustCredentialID(t, testCredentialID),
		ProfileID:           profile.ID(),
		IssuerID:            issuer,
		State:               enrollment.CredentialStateActive,
		UseLimit:            useLimit,
		IssuedRecoveryEpoch: 7,
		ValidFrom:           testNow.Add(-time.Hour),
		ExpiresAt:           testNow.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	deploymentID, err := deployment.ParseID(testDeploymentID)
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	authority, err := appintake.NewAuthority(appintake.AuthorityParams{
		DeploymentID:  deploymentID,
		Scope:         scope,
		Profile:       profile,
		Credential:    credential,
		Digest:        testDigest(t),
		RecoveryEpoch: 7,
	})
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	return authority
}

func validCommand(
	t *testing.T,
	authority appintake.Authority,
	registrationID enrollment.RegistrationID,
) registration.Command {
	t.Helper()
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatalf("ParseHostname() error = %v", err)
	}
	return registration.Command{
		RegistrationID: registrationID,
		Scope:          authority.Scope(),
		CredentialID:   authority.Credential().ID(),
		Identity:       validIdentity(t),
		Hostname:       hostname,
		RecoveryEpoch:  authority.RecoveryEpoch(),
	}
}

func validChange(
	t *testing.T,
	authority appintake.Authority,
	lookup appintake.Lookup,
) appintake.Change {
	t.Helper()
	command := validCommand(t, authority, lookup.RegistrationID)
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	pending, err := enrollment.NewRegistration(enrollment.RegistrationParams{
		ID:                 command.RegistrationID,
		Scope:              command.Scope,
		ProfileID:          authority.Profile().ID(),
		MachineFingerprint: lookup.MachineFingerprint,
		State:              enrollment.RegistrationStatePending,
		CreatedAt:          testNow,
		ExpiresAt:          testNow.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("NewRegistration() error = %v", err)
	}
	values := []string{
		"01890f60-0000-7000-8000-000000000010",
		"01890f60-0000-7000-8000-000000000011",
		"01890f60-0000-7000-8000-000000000012",
	}
	ids := make([]publicid.ID, len(values))
	for index, value := range values {
		ids[index], err = publicid.Parse(value)
		if err != nil {
			t.Fatalf("publicid.Parse(%q) error = %v", value, err)
		}
	}
	evidenceIDs, err := appintake.NewEvidenceIDs(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatalf("NewEvidenceIDs() error = %v", err)
	}
	change, err := appintake.NewChange(command, pending, hash, evidenceIDs, testNow)
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	return change
}

func testDigest(t *testing.T) enrollment.CredentialDigest {
	t.Helper()
	keyID, err := enrollment.NewDigestKeyID("test-key-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	var value [32]byte
	for index := range value {
		value[index] = 0x5a
	}
	digest, err := enrollment.NewCredentialDigest(keyID, value)
	if err != nil {
		t.Fatalf("NewCredentialDigest() error = %v", err)
	}
	return digest
}

func validIdentity(t *testing.T) node.RegistrationIdentity {
	t.Helper()
	var machineKeyBytes, nodeKeyBytes [32]byte
	for index := range machineKeyBytes {
		machineKeyBytes[index] = 0x21
		nodeKeyBytes[index] = 0x22
	}
	machineKey, err := node.NewMachineKey(machineKeyBytes)
	if err != nil {
		t.Fatalf("NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey(nodeKeyBytes)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	identityValue, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatalf("NewRegistrationIdentity() error = %v", err)
	}
	return identityValue
}

func mustScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID(testWorkspaceID)
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID(testNetworkID)
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func mustRegistrationID(t *testing.T, value string) enrollment.RegistrationID {
	t.Helper()
	id, err := enrollment.ParseRegistrationID(value)
	if err != nil {
		t.Fatalf("ParseRegistrationID(%q) error = %v", value, err)
	}
	return id
}

func mustCredentialID(t *testing.T, value string) enrollment.CredentialID {
	t.Helper()
	id, err := enrollment.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("ParseCredentialID(%q) error = %v", value, err)
	}
	return id
}

func mustProfileID(t *testing.T, value string) enrollment.ProfileID {
	t.Helper()
	id, err := enrollment.ParseProfileID(value)
	if err != nil {
		t.Fatalf("ParseProfileID(%q) error = %v", value, err)
	}
	return id
}

func callQueries(calls []testCall) []string {
	queries := make([]string, 0, len(calls))
	for _, call := range calls {
		queries = append(queries, call.query)
	}
	return queries
}

func findCall(t *testing.T, calls []testCall, query string) testCall {
	t.Helper()
	for _, call := range calls {
		if call.query == query {
			return call
		}
	}
	t.Fatalf("query not called: %s", query)
	return testCall{}
}

func postgresError(code string, constraint string) error {
	return &pgconn.PgError{Code: code, ConstraintName: constraint}
}
