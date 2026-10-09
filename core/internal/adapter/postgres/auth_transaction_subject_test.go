package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestSubjectReadUsesExactBoundedReadOnlyUnit(t *testing.T) {
	t.Parallel()
	for _, previous := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "active and previous"}[previous], func(t *testing.T) {
			t.Parallel()
			query := authSubjectLookupFixture(t, previous)
			transaction := newFakeAuthTransactionDatabaseTransaction()
			transaction.enqueueRow(resolveLoginSubjectSQL, authSubjectRow(query, nil))
			database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.ResolveLoginSubject(t.Context(), query)
			if err != nil || !result.Matches(query) {
				t.Fatal("exact read failed")
			}
			if len(database.readOnly) != 1 || !database.readOnly[0] || len(transaction.calls) != 2 || transaction.calls[0].query != configureAuthTransactionSQL || transaction.calls[1].query != resolveLoginSubjectSQL {
				t.Fatal("read mutated authority or lacked local budgets")
			}
			if transaction.commitCalls != 1 || transaction.rollbackCalls != 0 {
				t.Fatal("read did not close once")
			}
			route := query.Snapshot().Route()
			hash := query.Snapshot().SemanticHash()
			digests := query.Digests()
			active := digests[0].Bytes()
			args := transaction.calls[1].arguments
			want := []any{route.DeploymentID().String(), route.ProviderID().String(), route.ClientID().String(), route.ProviderGeneration(), route.RecoveryEpoch(), route.Issuer(), route.DiscoveryURI(), route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI(), route.OIDCClientID(), route.ClientAuthMethod(), route.Scopes(), route.AllowedAlgorithms(), route.RedirectURI(), query.Snapshot().TransactionID().String(), int64(2), hash[:], query.Claimed().ConsumedAt(), route.RedirectID(), route.ReturnRouteID(), digests[0].Algorithm(), digests[0].KeyID().String(), active[:]}
			if len(args) != 26 || !reflect.DeepEqual(args[:24], want) {
				t.Fatal("claim/route/digest substitution in SQL arguments")
			}
			if previous {
				previousDigest := digests[1].Bytes()
				if args[24].(*string) == nil || *args[24].(*string) != digests[1].KeyID().String() || !reflect.DeepEqual(args[25], previousDigest[:]) {
					t.Fatal("previous candidate omitted or reordered")
				}
			} else if args[24].(*string) != nil || args[25].([]byte) != nil {
				t.Fatal("absent previous candidate invented")
			}
		})
	}
}

func TestSubjectReadRejectsEveryMalformedEvidenceField(t *testing.T) {
	t.Parallel()
	for _, candidate := range []struct {
		name  string
		index int
		value any
	}{
		{name: "transaction", index: 0, value: "01890f00-0000-7000-8000-000000000099"},
		{name: "version", index: 1, value: int64(3)},
		{name: "claim time", index: 2, value: time.Time{}},
		{name: "short binding hash", index: 3, value: make([]byte, 31)},
		{name: "wrong binding hash", index: 3, value: make([]byte, 32)},
		{name: "principal", index: 4, value: "bad"},
		{name: "subject", index: 5, value: "bad"},
		{name: "membership", index: 6, value: "bad"},
		{name: "subject version", index: 7, value: int64(0)},
		{name: "account version", index: 8, value: int64(0)},
		{name: "membership version", index: 9, value: int64(0)},
		{name: "principal generation", index: 10, value: int64(0)},
		{name: "session generation", index: 11, value: int64(0)},
		{name: "membership generation", index: 12, value: int64(0)},
		{name: "algorithm", index: 13, value: "sha256-v1"},
		{name: "unknown key", index: 14, value: "unknown-v1"},
		{name: "malformed key", index: 14, value: "bad key"},
		{name: "short digest", index: 15, value: make([]byte, 31)},
		{name: "long digest", index: 15, value: make([]byte, 33)},
		{name: "zero digest", index: 15, value: make([]byte, 32)},
		{name: "evaluation time", index: 16, value: time.Time{}},
		{name: "noncanonical evaluation", index: 16, value: authSubjectLookupFixture(t, false).Claimed().ConsumedAt().Add(time.Nanosecond)},
		{name: "evaluation before claim", index: 16, value: authSubjectLookupFixture(t, false).Claimed().ConsumedAt().Add(-time.Microsecond)},
		{name: "expired claim", index: 16, value: authSubjectLookupFixture(t, false).Snapshot().ExpiresAt()},
		{name: "expired membership", index: 17, value: subjectTimePointer(authSubjectLookupFixture(t, false).Claimed().ConsumedAt())},
		{name: "noncanonical membership", index: 17, value: subjectTimePointer(authSubjectLookupFixture(t, false).Claimed().ConsumedAt().Add(time.Second + time.Nanosecond))},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			t.Parallel()
			query := authSubjectLookupFixture(t, false)
			transaction := newFakeAuthTransactionDatabaseTransaction()
			transaction.enqueueRow(resolveLoginSubjectSQL, authSubjectRow(query, func(destinations []any) {
				reflect.ValueOf(destinations[candidate.index]).Elem().Set(reflect.ValueOf(candidate.value))
			}))
			store, err := newAuthTransactionStore(&fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.ResolveLoginSubject(t.Context(), query)
			if !errors.Is(err, oidcauth.ErrSubjectResolutionRejected) || result.IsValid() || transaction.commitCalls != 0 || transaction.rollbackCalls != 1 {
				t.Fatal("malformed evidence escaped closed read")
			}
		})
	}
}

func subjectTimePointer(value time.Time) *time.Time { return &value }

func TestSubjectReadRejectsInvalidAdmissionWithoutDatabase(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"nil context", "canceled context", "zero query", "nil store"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			database := &fakeAuthTransactionDatabase{}
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			query := authSubjectLookupFixture(t, false)
			switch name {
			case "nil context":
				ctx = nil
			case "canceled context":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "zero query":
				query = oidcauth.SubjectLookup{}
			case "nil store":
				store = nil
			}
			result, err := store.ResolveLoginSubject(ctx, query)
			if err == nil || result.IsValid() || len(database.readOnly) != 0 {
				t.Fatal("invalid admission touched database")
			}
		})
	}
}

func TestSubjectReadJoinsOwnedBeginFailureAndMasksRawDependencies(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"owned begin", "nil begin", "configure", "query", "commit", "rollback"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			transaction := newFakeAuthTransactionDatabaseTransaction()
			query := authSubjectLookupFixture(t, true)
			transaction.enqueueRow(resolveLoginSubjectSQL, authSubjectRow(query, func(destinations []any) {
				digest := query.Digests()[1]
				value := digest.Bytes()
				*destinations[14].(*string) = digest.KeyID().String()
				*destinations[15].(*[]byte) = value[:]
			}))
			private := errors.New("private connection and subject")
			database := subjectOwnedBeginDatabase{transaction: transaction}
			switch stage {
			case "owned begin":
				database.err = private
			case "nil begin":
				database.transaction = nil
			case "configure":
				transaction.execErrors[configureAuthTransactionSQL] = []error{private}
			case "query":
				transaction.rows[resolveLoginSubjectSQL] = []authTransactionRow{authTransactionTestRow{err: private}}
			case "commit":
				transaction.commitErr = private
			case "rollback":
				transaction.rows[resolveLoginSubjectSQL] = []authTransactionRow{authTransactionTestRow{err: pgx.ErrNoRows}}
				transaction.rollbackErr = private
			}
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.ResolveLoginSubject(t.Context(), query)
			if !errors.Is(err, oidcauth.ErrSubjectResolutionUnavailable) || result.IsValid() || strings.Contains(err.Error(), "private") {
				t.Fatal("failed read disclosed or released evidence")
			}
			if stage != "nil begin" && transaction.rollbackCalls != 1 {
				t.Fatal("owned failure cleanup not joined")
			}
		})
	}
}

type subjectOwnedBeginDatabase struct {
	transaction authTransactionDatabaseTransaction
	err         error
}

func (database subjectOwnedBeginDatabase) Begin(context.Context, bool) (authTransactionDatabaseTransaction, error) {
	return database.transaction, database.err
}

func TestSubjectReadRejectsDependencyAndCompletionFailures(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"begin", "configure", "missing", "query", "commit lost ACK", "cleanup"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			query := authSubjectLookupFixture(t, false)
			transaction := newFakeAuthTransactionDatabaseTransaction()
			transaction.enqueueRow(resolveLoginSubjectSQL, authSubjectRow(query, nil))
			database := &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{transaction}}
			private := &pgconn.PgError{Code: "XX000", Message: "private identity", Detail: "private subject"}
			switch name {
			case "begin":
				database.beginErr = private
			case "configure":
				transaction.execErrors[configureAuthTransactionSQL] = []error{private}
			case "missing":
				transaction.rows[resolveLoginSubjectSQL] = []authTransactionRow{authTransactionTestRow{err: pgx.ErrNoRows}}
			case "query":
				transaction.rows[resolveLoginSubjectSQL] = []authTransactionRow{authTransactionTestRow{err: private}}
			case "commit lost ACK":
				transaction.commitErr = private
			case "cleanup":
				transaction.rows[resolveLoginSubjectSQL] = []authTransactionRow{authTransactionTestRow{err: pgx.ErrNoRows}}
				transaction.rollbackErr = private
			}
			store, err := newAuthTransactionStore(database, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.ResolveLoginSubject(t.Context(), query)
			if err == nil || result.IsValid() || strings.Contains(err.Error(), "private") || errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) {
				t.Fatal("failed read released evidence/detail or implied write resolution")
			}
			if len(database.readOnly) != 1 || transaction.commitCalls > 1 {
				t.Fatal("read retried")
			}
			if name != "begin" && transaction.rollbackCalls != 1 {
				t.Fatal("failed read did not join cleanup")
			}
		})
	}
}

func TestSubjectReadPropagatesCancellationAndFiniteCleanup(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"configure", "query", "commit"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			query := authSubjectLookupFixture(t, false)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			transaction := newFakeAuthTransactionDatabaseTransaction()
			transaction.enqueueRow(resolveLoginSubjectSQL, authSubjectRow(query, nil))
			wrapped := &admissionContextTransaction{fakeAuthTransactionDatabaseTransaction: transaction, t: t, stage: stage, cancel: cancel}
			store, err := newAuthTransactionStore(&admissionContextDatabase{transaction: wrapped, t: t}, testAuthTransactionOptions(), nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.ResolveLoginSubject(ctx, query)
			if !errors.Is(err, context.Canceled) || result.IsValid() {
				t.Fatal("canceled read released evidence")
			}
			if stage != "commit" && transaction.commitCalls != 0 {
				t.Fatal("canceled read continued to completion")
			}
		})
	}
}

func authSubjectLookupFixture(t *testing.T, previous bool) oidcauth.SubjectLookup {
	t.Helper()
	snapshot := authClaimCommandFixture(t).Snapshot()
	claimed, err := oidcauth.NewClaimed(snapshot, 2, snapshot.CreatedAt().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	id, err := oidcauth.NewDigestKeyID("subject-active-v1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := oidcauth.NewSubjectDigest(id, [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	digests := []oidcauth.SubjectDigest{digest}
	if previous {
		id, err = oidcauth.NewDigestKeyID("subject-previous-v1")
		if err != nil {
			t.Fatal(err)
		}
		digest, err = oidcauth.NewSubjectDigest(id, [32]byte{8})
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, digest)
	}
	query, err := oidcauth.NewSubjectLookup(claimed, digests)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func authSubjectRow(query oidcauth.SubjectLookup, mutate func([]any)) authTransactionRow {
	return authTransactionTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = query.Snapshot().TransactionID().String()
		*destinations[1].(*int64) = 2
		*destinations[2].(*time.Time) = query.Claimed().ConsumedAt()
		hash := query.Snapshot().SemanticHash()
		*destinations[3].(*[]byte) = hash[:]
		*destinations[4].(*string) = "01890f00-0000-7000-8000-000000000011"
		*destinations[5].(*string) = "01890f00-0000-7000-8000-000000000711"
		*destinations[6].(*string) = "01890f00-0000-7000-8000-000000000901"
		for index := 7; index <= 12; index++ {
			*destinations[index].(*int64) = 1
		}
		digest := query.Digests()[0]
		*destinations[13].(*string) = digest.Algorithm()
		*destinations[14].(*string) = digest.KeyID().String()
		value := digest.Bytes()
		*destinations[15].(*[]byte) = value[:]
		*destinations[16].(*time.Time) = query.Claimed().ConsumedAt()
		*destinations[17].(**time.Time) = nil
		*destinations[18].(*string) = "01890f00-0000-7000-8000-000000000002"
		if mutate != nil {
			mutate(destinations)
		}
		return nil
	}}
}
