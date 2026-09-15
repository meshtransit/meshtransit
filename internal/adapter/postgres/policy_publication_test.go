package postgres

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
)

func TestPolicyPublicationTransactionCommitsReleaseRevisionAuditAndOutbox(t *testing.T) {
	t.Parallel()

	command := policyPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	enqueuePolicyPublicationApply(databaseTransaction, 6, 2)
	store := beginTestPolicyPublicationStore(t, databaseTransaction)

	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("PolicyPublicationStore.Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change := policyPublicationChangeFixture(t, command, resolution)
	result, err := transaction.Apply(t.Context(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.ReleaseID() != change.MutationIDs().ReleaseID() ||
		result.NetworkRevision() != 6 || result.PolicyRevision() != 2 {
		t.Fatalf("Apply() result = %+v, want release revision 6/2", result)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	wantCalls := []string{
		configurePolicyPublicationTransactionSQL,
		setPolicyPublicationScopeSQL,
		lockPolicyPublicationRevisionSQL,
		lockActivePolicyReleaseSQL,
		lockPolicyPublicationAuditStreamSQL,
		setPolicyPublicationChangeSQL,
		publishCompiledPolicySQL,
		appendPolicyPublicationEvidenceSQL,
	}
	if got := policyPublicationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("database call order mismatch\ngot:  %#v\nwant: %#v", got, wantCalls)
	}
	publishCall := findPolicyPublicationCall(t, databaseTransaction.calls, publishCompiledPolicySQL)
	if len(publishCall.arguments) != 6 || publishCall.arguments[0] != change.MutationIDs().ReleaseID().String() ||
		publishCall.arguments[1] != int64(1) || publishCall.arguments[3] != 1 {
		t.Fatalf("publish arguments = %#v, want release/base/compiler binding", publishCall.arguments)
	}
	var rules []policyPublicationRulePayload
	if err := json.Unmarshal(publishCall.arguments[5].([]byte), &rules); err != nil {
		t.Fatalf("decode published rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ProjectionPublicID != change.MutationIDs().ProjectionIDs()[0].String() ||
		rules[0].Protocol != "tcp" || !reflect.DeepEqual(rules[0].PortRangeFirst, []int{443}) ||
		!reflect.DeepEqual(rules[0].PortRangeLast, []int{443}) {
		t.Fatalf("published rules = %+v, want exact canonical projection", rules)
	}
	evidenceCall := findPolicyPublicationCall(
		t,
		databaseTransaction.calls,
		appendPolicyPublicationEvidenceSQL,
	)
	if len(evidenceCall.arguments) != 16 || evidenceCall.arguments[7] != int64(1) ||
		evidenceCall.arguments[8] != int64(6) || evidenceCall.arguments[10] != "policy.published" {
		t.Fatalf("evidence arguments = %#v, want revision-bound audit/outbox", evidenceCall.arguments)
	}
}

func TestPolicyPublicationTransactionMapsStaleCASConflict(t *testing.T) {
	t.Parallel()

	command := policyPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	databaseTransaction.enqueueRow(publishCompiledPolicySQL, policyPublicationTestRow{
		err: &pgconn.PgError{Code: "MT001", Message: "controlled stale base"},
	})
	store := beginTestPolicyPublicationStore(t, databaseTransaction)
	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	_, err = transaction.Apply(t.Context(), policyPublicationChangeFixture(t, command, resolution))
	if !errors.Is(err, ErrApplyPolicyPublication) || !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("Apply() error = %v, want classified ErrConflict", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestPolicyPublicationStoreResolvesCommittedRelease(t *testing.T) {
	t.Parallel()

	command := policyPublicationCommandFixture(t)
	ids := policyPublicationMutationIDsFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationSetup(databaseTransaction)
	hash := command.Candidate().SemanticHash().Bytes()
	databaseTransaction.enqueueRow(loadCommittedPolicyReleaseSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 6
			*destinations[1].(*int64) = 2
			*destinations[2].(*[]byte) = append([]byte(nil), hash[:]...)
			return nil
		},
	})
	database := &fakePolicyPublicationDatabase{transactions: []*fakePolicyPublicationTransaction{
		databaseTransaction,
	}}
	store, err := newPolicyPublicationStore(database, testPolicyPublicationOptions(), nil)
	if err != nil {
		t.Fatalf("newPolicyPublicationStore() error = %v", err)
	}

	result, found, err := store.ResolveCommitted(t.Context(), command, ids.ReleaseID())
	if err != nil {
		t.Fatalf("ResolveCommitted() error = %v", err)
	}
	if !found || !result.IsValid() || result.ReleaseID() != ids.ReleaseID() ||
		result.NetworkRevision() != 6 || result.PolicyRevision() != 2 ||
		databaseTransaction.commitCalls != 1 || databaseTransaction.rollbackCalls != 0 {
		t.Fatalf("ResolveCommitted() = (%+v, %t), want committed release", result, found)
	}
	if len(database.readOnly) != 1 || !database.readOnly[0] {
		t.Fatalf("database read-only begins = %v, want [true]", database.readOnly)
	}
}

func TestPolicyPublicationStoreRejectsUnsafeConstruction(t *testing.T) {
	t.Parallel()

	if _, err := newPolicyPublicationStore(nil, testPolicyPublicationOptions(), nil); !errors.Is(
		err,
		ErrInvalidPolicyPublicationStore,
	) {
		t.Fatalf("newPolicyPublicationStore() error = %v, want invalid store", err)
	}
	options := testPolicyPublicationOptions()
	options.LockTimeout = 0
	if _, err := newPolicyPublicationStore(
		&fakePolicyPublicationDatabase{},
		options,
		nil,
	); !errors.Is(err, ErrInvalidPolicyPublicationStore) {
		t.Fatalf("newPolicyPublicationStore() unsafe timeout error = %v", err)
	}
}

func TestNewPolicyPublicationStoreRequiresRuntimePool(t *testing.T) {
	t.Parallel()

	options := testPolicyPublicationOptions()
	for name, pool := range map[string]*Pool{
		"nil":              nil,
		"worker":           {role: PoolRoleWorker, policyPublicationDatabase: &fakePolicyPublicationDatabase{}},
		"missing database": {role: PoolRoleRuntime},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPolicyPublicationStore(pool, options); !errors.Is(
				err,
				ErrInvalidPolicyPublicationStore,
			) {
				t.Fatalf("NewPolicyPublicationStore() error = %v, want invalid store", err)
			}
		})
	}
	runtimePool := &Pool{
		role:                      PoolRoleRuntime,
		policyPublicationDatabase: &fakePolicyPublicationDatabase{},
	}
	if _, err := NewPolicyPublicationStore(runtimePool, options); err != nil {
		t.Fatalf("NewPolicyPublicationStore(runtime) error = %v", err)
	}
}
