package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

func TestAccountSessionStoreResolvesExactAuthority(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	workspacePublicID := "01890f00-0000-7000-8000-000000000101"
	acr := "urn:meshtransit:assurance:mfa"
	transaction := &fakeAccountSessionTransaction{
		row: fakeAccountSessionRow{values: []any{
			"01890f00-0000-7000-8000-000000000811",
			"01890f00-0000-7000-8000-000000000001",
			"01890f00-0000-7000-8000-000000000011",
			"01890f00-0000-7000-8000-000000000711",
			&workspacePublicID,
			now.Add(-time.Minute),
			&acr,
			[]string{"pwd", "mfa"},
			int64(2),
			int64(3),
			int64(4),
			int64(5),
			int64(7),
			now.Add(time.Hour),
			now.Add(8 * time.Hour),
		}},
	}
	store, err := newAccountSessionStore(
		&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second},
		nil,
	)
	if err != nil {
		t.Fatalf("newAccountSessionStore() error = %v", err)
	}
	deploymentID := accountSessionDeploymentID(t)
	digest := accountSessionDigest(t)
	session, found, err := store.Resolve(t.Context(), deploymentID, 7, digest)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !found || session.DeploymentID() != deploymentID ||
		session.DeploymentRecoveryEpoch() != 7 || session.PrincipalID().String() !=
		"01890f00-0000-7000-8000-000000000011" {
		t.Fatal("Resolve() returned incomplete Account Session authority")
	}
	if transaction.commits != 1 || transaction.rollbacks != 0 ||
		len(transaction.arguments) != 5 ||
		transaction.arguments[0] != deploymentID.String() ||
		transaction.arguments[1] != int64(7) ||
		transaction.arguments[2] != accountsession.DigestAlgorithmHMACSHA256V1 ||
		transaction.arguments[3] != "integration-v1" {
		t.Fatalf(
			"transaction commit/rollback/arguments = %d/%d/%v",
			transaction.commits,
			transaction.rollbacks,
			transaction.arguments,
		)
	}
}

func TestAccountSessionStoreReturnsNotFoundWithoutLeakingEvidence(t *testing.T) {
	t.Parallel()

	transaction := &fakeAccountSessionTransaction{
		row: fakeAccountSessionRow{err: pgx.ErrNoRows},
	}
	store, err := newAccountSessionStore(
		&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second},
		nil,
	)
	if err != nil {
		t.Fatalf("newAccountSessionStore() error = %v", err)
	}
	session, found, err := store.Resolve(
		t.Context(),
		accountSessionDeploymentID(t),
		7,
		accountSessionDigest(t),
	)
	if err != nil || found || session.IsValid() {
		t.Fatalf("Resolve() = (%+v, %t, %v), want empty not found", session, found, err)
	}
	if transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("transaction commit/rollback = %d/%d, want 1/0", transaction.commits, transaction.rollbacks)
	}
}

func TestAccountSessionStoreRollsBackMalformedEvidence(t *testing.T) {
	t.Parallel()

	transaction := &fakeAccountSessionTransaction{
		row: fakeAccountSessionRow{values: make([]any, 15)},
	}
	store, err := newAccountSessionStore(
		&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second},
		nil,
	)
	if err != nil {
		t.Fatalf("newAccountSessionStore() error = %v", err)
	}
	_, _, err = store.Resolve(
		t.Context(),
		accountSessionDeploymentID(t),
		7,
		accountSessionDigest(t),
	)
	if !errors.Is(err, ErrAccountSessionEvidence) {
		t.Fatalf("Resolve() error = %v, want ErrAccountSessionEvidence", err)
	}
	if transaction.commits != 0 || transaction.rollbacks != 1 {
		t.Fatalf("transaction commit/rollback = %d/%d, want 0/1", transaction.commits, transaction.rollbacks)
	}
}

func accountSessionDeploymentID(t *testing.T) deployment.ID {
	t.Helper()
	id, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	return id
}

func accountSessionDigest(t *testing.T) accountsession.Digest {
	t.Helper()
	keyID, err := accountsession.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatalf("accountsession.NewDigestKeyID() error = %v", err)
	}
	var value [32]byte
	value[0] = 1
	digest, err := accountsession.NewDigest(keyID, value)
	if err != nil {
		t.Fatalf("accountsession.NewDigest() error = %v", err)
	}
	return digest
}

type fakeAccountSessionDatabase struct {
	transaction *fakeAccountSessionTransaction
	err         error
}

func (database *fakeAccountSessionDatabase) Begin(
	context.Context,
) (accountSessionTransaction, error) {
	if database.err != nil {
		return nil, database.err
	}
	return database.transaction, nil
}

type fakeAccountSessionTransaction struct {
	row       fakeAccountSessionRow
	rows      []fakeAccountSessionRow
	arguments []any
	commits   int
	rollbacks int
}

func (*fakeAccountSessionTransaction) Exec(context.Context, string, ...any) error {
	return nil
}

func (transaction *fakeAccountSessionTransaction) QueryRow(
	_ context.Context,
	_ string,
	arguments ...any,
) accountSessionRow {
	transaction.arguments = arguments
	if len(transaction.rows) > 0 {
		row := transaction.rows[0]
		transaction.rows = transaction.rows[1:]
		return row
	}
	return transaction.row
}

func (transaction *fakeAccountSessionTransaction) Commit(context.Context) error {
	transaction.commits++
	return nil
}

func (transaction *fakeAccountSessionTransaction) Rollback(context.Context) error {
	transaction.rollbacks++
	return nil
}

type fakeAccountSessionRow struct {
	values []any
	err    error
}

func (row fakeAccountSessionRow) Scan(targets ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(row.values) != len(targets) {
		return ErrAccountSessionEvidence
	}
	for index, value := range row.values {
		target := reflect.ValueOf(targets[index])
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return ErrAccountSessionEvidence
		}
		if value == nil {
			target.Elem().SetZero()
			continue
		}
		source := reflect.ValueOf(value)
		if !source.Type().AssignableTo(target.Elem().Type()) {
			return ErrAccountSessionEvidence
		}
		target.Elem().Set(source)
	}
	return nil
}
