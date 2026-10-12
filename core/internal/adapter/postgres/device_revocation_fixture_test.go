package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/revocation"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/idempotency"
)

type deviceRevocationTestCall struct {
	query     string
	arguments []any
}

type fakeDeviceRevocationDatabase struct {
	transactions []*fakeDeviceRevocationTransaction
	readOnly     []bool
	beginErr     error
}

func (database *fakeDeviceRevocationDatabase) Begin(
	_ context.Context,
	readOnly bool,
) (deviceRevocationDatabaseTransaction, error) {
	database.readOnly = append(database.readOnly, readOnly)
	if database.beginErr != nil {
		return nil, database.beginErr
	}
	if len(database.transactions) == 0 {
		return nil, errors.New("no queued Device revocation transaction")
	}
	transaction := database.transactions[0]
	database.transactions = database.transactions[1:]
	return transaction, nil
}

type fakeDeviceRevocationTransaction struct {
	rows          map[string][]deviceRevocationRow
	execErrors    map[string][]error
	calls         []deviceRevocationTestCall
	commitErr     error
	rollbackErr   error
	commitCalls   int
	rollbackCalls int
}

func newFakeDeviceRevocationTransaction() *fakeDeviceRevocationTransaction {
	return &fakeDeviceRevocationTransaction{
		rows:       make(map[string][]deviceRevocationRow),
		execErrors: make(map[string][]error),
	}
}

func (transaction *fakeDeviceRevocationTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) error {
	transaction.record(query, arguments)
	queued := transaction.execErrors[query]
	if len(queued) == 0 {
		return nil
	}
	transaction.execErrors[query] = queued[1:]
	return queued[0]
}

func (transaction *fakeDeviceRevocationTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) deviceRevocationRow {
	transaction.record(query, arguments)
	queued := transaction.rows[query]
	if len(queued) == 0 {
		return deviceRevocationTestRow{err: fmt.Errorf("unexpected Device revocation query: %s", query)}
	}
	transaction.rows[query] = queued[1:]
	return queued[0]
}

func (transaction *fakeDeviceRevocationTransaction) Commit(context.Context) error {
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakeDeviceRevocationTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakeDeviceRevocationTransaction) enqueueRow(
	query string,
	row deviceRevocationRow,
) {
	transaction.rows[query] = append(transaction.rows[query], row)
}

func (transaction *fakeDeviceRevocationTransaction) record(query string, arguments []any) {
	transaction.calls = append(transaction.calls, deviceRevocationTestCall{
		query:     query,
		arguments: append([]any(nil), arguments...),
	})
}

type deviceRevocationTestRow struct {
	scan func(...any) error
	err  error
}

func (row deviceRevocationTestRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if row.scan == nil {
		return nil
	}
	return row.scan(destinations...)
}

func testDeviceRevocationOptions() DeviceRevocationOptions {
	return DeviceRevocationOptions{
		StatementTimeout: 5 * time.Second,
		LockTimeout:      time.Second,
		IdleTimeout:      10 * time.Second,
	}
}

func beginTestDeviceRevocationStore(
	t *testing.T,
	databaseTransaction *fakeDeviceRevocationTransaction,
) *DeviceRevocationStore {
	t.Helper()
	store, err := newDeviceRevocationStore(
		&fakeDeviceRevocationDatabase{transactions: []*fakeDeviceRevocationTransaction{
			databaseTransaction,
		}},
		testDeviceRevocationOptions(),
		nil,
	)
	if err != nil {
		t.Fatalf("newDeviceRevocationStore() error = %v", err)
	}
	return store
}

func enqueueDeviceRevocationSetup(transaction *fakeDeviceRevocationTransaction) {
	transaction.enqueueRow(setDeviceRevocationScopeSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 101
			*destinations[1].(*int64) = 201
			return nil
		},
	})
}

func enqueueNewDeviceRevocationResolution(
	t *testing.T,
	transaction *fakeDeviceRevocationTransaction,
	command revocation.Command,
	attempt revocation.Attempt,
) {
	t.Helper()
	enqueueDeviceRevocationSetup(transaction)
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	enqueueDeviceRevocationAuthorization(transaction, attempt.OccurredAt())
	transaction.enqueueRow(claimDeviceRevocationIdempotencySQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = attempt.MutationIDs().IdempotencyRecordID().String()
			hash := requestHash.Bytes()
			*destinations[1].(*[]byte) = append([]byte(nil), hash[:]...)
			*destinations[2].(*string) = "pending"
			*destinations[3].(*string) = ""
			*destinations[4].(*string) = ""
			*destinations[5].(*int64) = 0
			*destinations[6].(*int64) = 0
			*destinations[7].(*string) = "{}"
			*destinations[8].(*time.Time) = attempt.ExpiresAt()
			*destinations[9].(*bool) = true
			return nil
		},
	})
	transaction.enqueueRow(lockDeviceRevocationRevisionSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			for index, value := range [...]int64{5, 7, 1, 1, 1, 1, 1, 1} {
				*destinations[index].(*int64) = value
			}
			return nil
		},
	})
	transaction.enqueueRow(lockDeviceRevocationTargetSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 301
			*destinations[1].(*int64) = 1
			*destinations[2].(*int64) = 1
			*destinations[3].(*string) = "active"
			*destinations[4].(*int64) = 1
			*destinations[5].(*int64) = 311
			*destinations[6].(*int64) = 1
			*destinations[7].(*string) = "active"
			*destinations[8].(*time.Time) = attempt.OccurredAt().Add(-time.Hour)
			*destinations[9].(*int64) = 1
			*destinations[10].(*int64) = 321
			*destinations[11].(*int64) = 1
			*destinations[12].(*string) = "active"
			*destinations[13].(*time.Time) = attempt.OccurredAt().Add(-time.Hour)
			return nil
		},
	})
	transaction.enqueueRow(lockDeviceRevocationAuditStreamSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 3
			*destinations[1].(*int64) = 4
			*destinations[2].(*[]byte) = make([]byte, 32)
			return nil
		},
	})
}

func enqueueDeviceRevocationApply(
	transaction *fakeDeviceRevocationTransaction,
	recordID publicid.ID,
) {
	transaction.enqueueRow(revokeDeviceSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 2
			*destinations[1].(*int64) = 2
			return nil
		},
	})
	for _, query := range [...]string{revokeMachineKeyEpochSQL, revokeNodeKeyEpochSQL} {
		transaction.enqueueRow(query, deviceRevocationTestRow{
			scan: func(destinations ...any) error {
				*destinations[0].(*int64) = 2
				return nil
			},
		})
	}
	transaction.enqueueRow(quarantineRevokedDeviceLeasesSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 2
			return nil
		},
	})
	transaction.enqueueRow(advanceDeviceRevocationRevisionSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 6
			*destinations[1].(*int64) = 8
			return nil
		},
	})
	transaction.enqueueRow(appendDeviceRevocationEvidenceSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 4
			return nil
		},
	})
	transaction.enqueueRow(completeDeviceRevocationIdempotencySQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = recordID.String()
			return nil
		},
	})
}

func enqueueCompletedDeviceRevocationRecord(
	t *testing.T,
	transaction *fakeDeviceRevocationTransaction,
	query string,
	command revocation.Command,
	recordID publicid.ID,
	expiresAt time.Time,
	withCreated bool,
) {
	t.Helper()
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	transaction.enqueueRow(query, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = recordID.String()
			hash := requestHash.Bytes()
			*destinations[1].(*[]byte) = append([]byte(nil), hash[:]...)
			*destinations[2].(*string) = "completed"
			*destinations[3].(*string) = deviceRevocationResultKind
			*destinations[4].(*string) = command.NodeID().String()
			*destinations[5].(*int64) = 2
			*destinations[6].(*int64) = 6
			*destinations[7].(*string) = fmt.Sprintf(
				`{"network_revision":6,"inventory_revision":8,"device_public_id":%q,"device_version":2,"session_generation":2,"terminal":true}`,
				command.NodeID().String(),
			)
			*destinations[8].(*time.Time) = expiresAt
			if withCreated {
				*destinations[9].(*bool) = false
			}
			return nil
		},
	})
}

func deviceRevocationCommandFixture(t *testing.T) revocation.Command {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	actorID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	reason, err := revocation.NewReason("compromised device")
	if err != nil {
		t.Fatalf("revocation.NewReason() error = %v", err)
	}
	var digest [32]byte
	digest[31] = 1
	proof, err := idempotency.NewProof("phase1-key-v1", digest)
	if err != nil {
		t.Fatalf("idempotency.NewProof() error = %v", err)
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope:               scope,
		NodeID:              nodeID,
		ExpectedVersion:     1,
		AccountSession:      deviceRevocationAccountSessionFixture(t, actorID, workspaceID),
		Reason:              reason,
		IdempotencyEvidence: proof,
	})
	if err != nil {
		t.Fatalf("revocation.NewCommand() error = %v", err)
	}
	return command
}

func enqueueDeviceRevocationAuthorization(
	transaction *fakeDeviceRevocationTransaction,
	evaluatedAt time.Time,
) {
	transaction.enqueueRow(authorizeDeviceRevocationSQL, deviceRevocationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = "01890f00-0000-7000-8000-000000000821"
			*destinations[1].(*string) = "01890f00-0000-7000-8000-000000000822"
			for index := 2; index <= 5; index++ {
				*destinations[index].(*int64) = 1
			}
			*destinations[6].(*bool) = false
			*destinations[7].(*time.Time) = evaluatedAt
			return nil
		},
	})
}

func deviceRevocationAccountSessionFixture(
	t *testing.T,
	principalID identity.PrincipalID,
	workspaceID workspace.ID,
) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	sessionID, err := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	if err != nil {
		t.Fatalf("accountsession.ParseID() error = %v", err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(
		"01890f00-0000-7000-8000-000000000611",
	)
	if err != nil {
		t.Fatalf("accountsession.ParseIdentitySubjectID() error = %v", err)
	}
	decisionTime := time.Date(2026, time.September, 16, 2, 0, 0, 0, time.UTC)
	session, err := accountsession.NewSession(accountsession.Params{
		ID:                           sessionID,
		DeploymentID:                 deploymentID,
		PrincipalID:                  principalID,
		IdentitySubjectID:            subjectID,
		LoginWorkspaceID:             workspaceID,
		HasLoginWorkspace:            true,
		AuthenticationTime:           decisionTime.Add(-time.Hour),
		ACR:                          "urn:meshtransit:test",
		AMR:                          []string{"pwd"},
		Version:                      1,
		PrincipalAuthorityGeneration: 1,
		AccountSessionGeneration:     1,
		ProviderGeneration:           1,
		DeploymentRecoveryEpoch:      1,
		IdleExpiresAt:                decisionTime.Add(time.Hour),
		AbsoluteExpiresAt:            decisionTime.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("accountsession.NewSession() error = %v", err)
	}
	return session
}

func deviceRevocationAttemptFixture(t *testing.T) revocation.Attempt {
	t.Helper()
	ids, err := revocation.NewMutationIDs(revocation.MutationIDParams{
		IdempotencyRecordID: deviceRevocationPublicIDFixture(t, "000000000901"),
		ChangeID:            deviceRevocationPublicIDFixture(t, "000000000902"),
		AuditEventID:        deviceRevocationPublicIDFixture(t, "000000000903"),
		OutboxEventID:       deviceRevocationPublicIDFixture(t, "000000000904"),
	})
	if err != nil {
		t.Fatalf("revocation.NewMutationIDs() error = %v", err)
	}
	occurredAt := time.Date(2026, time.September, 16, 2, 0, 0, 0, time.UTC)
	attempt, err := revocation.NewAttempt(ids, occurredAt, occurredAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("revocation.NewAttempt() error = %v", err)
	}
	return attempt
}

func deviceRevocationPublicIDFixture(t *testing.T, suffix string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}

func deviceRevocationCallQueries(calls []deviceRevocationTestCall) []string {
	queries := make([]string, len(calls))
	for index, call := range calls {
		queries[index] = call.query
	}
	return queries
}
