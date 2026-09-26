package postgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

func TestAccountSessionLogoutStoreRevokesExactAuthority(t *testing.T) {
	t.Parallel()
	transaction := &fakeAccountSessionLogoutTransaction{row: fakeAccountSessionLogoutRow{
		values: []any{
			"01890f00-0000-7000-8000-000000000811",
			int64(2),
			"01890f00-0000-7000-8000-000000000812",
			time.Date(2026, time.September, 26, 4, 5, 6, 0, time.UTC),
		},
	}}
	store := newAccountSessionLogoutStoreFixture(t, transaction)
	deploymentID := accountSessionDeploymentID(t)
	digest := accountSessionDigest(t)
	id, version, found, err := store.Revoke(t.Context(), deploymentID, 7, digest)
	if err != nil || !found || id.String() != "01890f00-0000-7000-8000-000000000811" || version != 2 {
		t.Fatal("Revoke() did not return exact durable evidence", err)
	}
	if transaction.commits != 1 || transaction.rollbacks != 0 || transaction.configures != 2 ||
		len(transaction.arguments) != 5 || transaction.arguments[0] != deploymentID.String() ||
		transaction.arguments[1] != int64(7) ||
		transaction.arguments[2] != accountsession.DigestAlgorithmHMACSHA256V1 ||
		transaction.arguments[3] != "integration-v1" {
		t.Fatal("logout transaction changed scope, configuration or commit ownership")
	}
	if len(transaction.appendArguments) != 11 {
		t.Fatal("logout transaction omitted audit/outbox evidence")
	}
	eventHash, eventHashOK := transaction.appendArguments[5].([]byte)
	afterHash, afterHashOK := transaction.appendArguments[9].([]byte)
	payload, payloadOK := transaction.appendArguments[10].([]byte)
	if !eventHashOK || !afterHashOK || !payloadOK || len(eventHash) != 32 || len(afterHash) != 32 ||
		bytes.Contains(payload, []byte("token")) || bytes.Contains(payload, []byte("digest")) ||
		bytes.Contains(payload, []byte("hmac")) {
		t.Fatal("logout evidence is incomplete or exposes secret-bearing fields")
	}
}

func TestAccountSessionLogoutStoreReplayIsCommittedNoMatch(t *testing.T) {
	t.Parallel()
	transaction := &fakeAccountSessionLogoutTransaction{row: fakeAccountSessionLogoutRow{err: pgx.ErrNoRows}}
	store := newAccountSessionLogoutStoreFixture(t, transaction)
	id, version, found, err := store.Revoke(
		t.Context(),
		accountSessionDeploymentID(t),
		7,
		accountSessionDigest(t),
	)
	if err != nil || found || id.IsValid() || version != 0 || transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatal("replay did not commit an exact idempotent no-match", err)
	}
}

func TestAccountSessionLogoutStoreRollsBackFailures(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"begin", "configure", "query", "malformed id", "malformed version", "commit"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			transaction := &fakeAccountSessionLogoutTransaction{row: fakeAccountSessionLogoutRow{
				values: []any{
					"01890f00-0000-7000-8000-000000000811",
					int64(2),
					"01890f00-0000-7000-8000-000000000812",
					time.Date(2026, time.September, 26, 4, 5, 6, 0, time.UTC),
				},
			}}
			database := &fakeAccountSessionLogoutDatabase{transaction: transaction}
			switch mode {
			case "begin":
				database.err = errors.New("private begin diagnostic")
			case "configure":
				transaction.configureErr = errors.New("private configure diagnostic")
			case "query":
				transaction.row.err = errors.New("private query diagnostic")
			case "malformed id":
				transaction.row.values[0] = "not-an-id"
			case "malformed version":
				transaction.row.values[1] = int64(1)
			case "commit":
				transaction.commitErr = errors.New("private commit diagnostic")
			}
			store, err := newAccountSessionLogoutStore(
				database,
				validAccountSessionLogoutOptionsFixture(),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, revokeErr := store.Revoke(
				t.Context(),
				accountSessionDeploymentID(t),
				7,
				accountSessionDigest(t),
			)
			if !errors.Is(revokeErr, ErrLogoutAccountSession) {
				t.Fatal("logout failure was not classified", revokeErr)
			}
			expectedRollbacks := 1
			if mode == "begin" {
				expectedRollbacks = 0
			}
			if transaction.commits > 1 || transaction.rollbacks != expectedRollbacks {
				t.Fatal("logout failure changed commit/rollback ownership")
			}
		})
	}
}

func TestAccountSessionLogoutStoreRejectsUnsafeConstructionAndInput(t *testing.T) {
	t.Parallel()
	if store, err := newAccountSessionLogoutStore(nil, validAccountSessionLogoutOptionsFixture(), nil); store != nil ||
		!errors.Is(err, ErrInvalidAccountSessionLogoutStore) {
		t.Fatal("nil database constructed logout store")
	}
	for _, options := range []AccountSessionLogoutOptions{
		{},
		{StatementTimeout: 31 * time.Second, LockTimeout: time.Second, IdleTimeout: time.Second},
		{StatementTimeout: time.Second, LockTimeout: 31 * time.Second, IdleTimeout: time.Second},
		{StatementTimeout: time.Second, LockTimeout: time.Second, IdleTimeout: 61 * time.Second},
	} {
		if store, err := newAccountSessionLogoutStore(&fakeAccountSessionLogoutDatabase{}, options, nil); store != nil ||
			!errors.Is(err, ErrInvalidAccountSessionLogoutStore) {
			t.Fatal("unsafe logout bounds constructed store")
		}
	}
	store := newAccountSessionLogoutStoreFixture(t, &fakeAccountSessionLogoutTransaction{})
	if _, _, _, err := store.Revoke(t.Context(), accountSessionDeploymentID(t), 0, accountSessionDigest(t)); !errors.Is(err, ErrInvalidAccountSessionLogoutStore) {
		t.Fatal("invalid recovery epoch reached database", err)
	}
}

func newAccountSessionLogoutStoreFixture(
	t *testing.T,
	transaction *fakeAccountSessionLogoutTransaction,
) *AccountSessionLogoutStore {
	t.Helper()
	store, err := newAccountSessionLogoutStore(
		&fakeAccountSessionLogoutDatabase{transaction: transaction},
		validAccountSessionLogoutOptionsFixture(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func validAccountSessionLogoutOptionsFixture() AccountSessionLogoutOptions {
	return AccountSessionLogoutOptions{
		StatementTimeout: time.Second,
		LockTimeout:      2 * time.Second,
		IdleTimeout:      3 * time.Second,
	}
}

type fakeAccountSessionLogoutDatabase struct {
	transaction *fakeAccountSessionLogoutTransaction
	err         error
}

func (database *fakeAccountSessionLogoutDatabase) Begin(
	context.Context,
) (accountSessionLogoutTransaction, error) {
	if database.err != nil {
		return nil, database.err
	}
	return database.transaction, nil
}

type fakeAccountSessionLogoutTransaction struct {
	row             fakeAccountSessionLogoutRow
	arguments       []any
	appendArguments []any
	configures      int
	commits         int
	rollbacks       int
	configureErr    error
	commitErr       error
}

func (transaction *fakeAccountSessionLogoutTransaction) Exec(
	context.Context,
	string,
	...any,
) error {
	transaction.configures++
	return transaction.configureErr
}

func (transaction *fakeAccountSessionLogoutTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) accountSessionLogoutRow {
	switch query {
	case logoutAccountSessionSQL:
		transaction.arguments = arguments
		return transaction.row
	case lockAccountSessionLogoutAuditStreamSQL:
		return fakeAccountSessionLogoutRow{values: []any{int64(91), int64(7), make([]byte, 32)}}
	case appendAccountSessionLogoutEvidenceSQL:
		transaction.appendArguments = arguments
		return fakeAccountSessionLogoutRow{values: []any{int64(7)}}
	default:
		return fakeAccountSessionLogoutRow{err: ErrAccountSessionLogoutEvidence}
	}
}

func (transaction *fakeAccountSessionLogoutTransaction) Commit(context.Context) error {
	transaction.commits++
	return transaction.commitErr
}

func (transaction *fakeAccountSessionLogoutTransaction) Rollback(context.Context) error {
	transaction.rollbacks++
	return nil
}

type fakeAccountSessionLogoutRow struct {
	values []any
	err    error
}

func (row fakeAccountSessionLogoutRow) Scan(targets ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(row.values) != len(targets) {
		return ErrAccountSessionLogoutEvidence
	}
	for index, value := range row.values {
		target := reflect.ValueOf(targets[index])
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return ErrAccountSessionLogoutEvidence
		}
		source := reflect.ValueOf(value)
		if !source.Type().AssignableTo(target.Elem().Type()) {
			return ErrAccountSessionLogoutEvidence
		}
		target.Elem().Set(source)
	}
	return nil
}
