package postgres

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
)

var policyPublicationTestTime = time.Date(2026, time.September, 16, 8, 0, 0, 0, time.UTC)

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
	resolution, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime)
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
	resolution, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime)
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

func TestPolicyPublicationTransactionRevalidatesAndPersistsResourceDestination(t *testing.T) {
	t.Parallel()

	command := policyResourcePublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	enqueuePolicyResourcePublicationApply(databaseTransaction, 6, 2)
	store := beginTestPolicyPublicationStore(t, databaseTransaction)
	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	resolution, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	change := policyPublicationChangeFixture(t, command, resolution)
	if _, err := transaction.Apply(t.Context(), change); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	wantCalls := []string{
		configurePolicyPublicationTransactionSQL,
		setPolicyPublicationScopeSQL,
		lockPolicyPublicationRevisionSQL,
		lockActivePolicyReleaseSQL,
		lockPolicyPublicationAuditStreamSQL,
		setPolicyPublicationChangeSQL,
		publishCompiledPolicySQL,
		attachPolicyResourceDestinationsSQL,
		appendPolicyPublicationEvidenceSQL,
	}
	if got := policyPublicationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("database call order mismatch\ngot:  %#v\nwant: %#v", got, wantCalls)
	}
	publishCall := findPolicyPublicationCall(t, databaseTransaction.calls, publishCompiledPolicySQL)
	var rules []policyPublicationRulePayload
	if err := json.Unmarshal(publishCall.arguments[5].([]byte), &rules); err != nil {
		t.Fatalf("decode published rules: %v", err)
	}
	if len(rules) != 1 || rules[0].DestinationResourcePublicID == "" ||
		rules[0].DestinationResourceVersion != 3 || rules[0].DestinationTargetGeneration != 2 ||
		rules[0].DestinationInventoryRevision != 7 ||
		len(rules[0].DestinationResourceSemanticHash) != 64 {
		t.Fatalf("published Resource rules = %+v, want exact pinned provenance", rules)
	}
	attachCall := findPolicyPublicationCall(
		t,
		databaseTransaction.calls,
		attachPolicyResourceDestinationsSQL,
	)
	if len(attachCall.arguments) != 3 ||
		attachCall.arguments[0] != change.MutationIDs().ReleaseID().String() {
		t.Fatalf("attach arguments = %#v, want release-bound Resource provenance", attachCall.arguments)
	}
}

func TestPolicyPublicationTransactionAuthorizesManagementSessionUnderLock(t *testing.T) {
	t.Parallel()

	command := policyManagementPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationSetup(databaseTransaction)
	enqueuePolicyPublicationAuthorization(databaseTransaction)
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	store := beginAuthorizedTestPolicyPublicationStore(t, databaseTransaction)

	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	if _, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !transaction.authorization.isValid() {
		t.Fatalf("authorization evidence = %+v, want valid", transaction.authorization)
	}
	call := findPolicyPublicationCall(t, databaseTransaction.calls, authorizePolicyPublicationSQL)
	if len(call.arguments) != 13 || call.arguments[11] != "policy.publish" ||
		call.arguments[12] != policyPublicationTestTime {
		t.Fatalf("authorization arguments = %#v", call.arguments)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestPolicyPublicationTransactionRejectsMissingManagementAuthority(t *testing.T) {
	t.Parallel()

	command := policyManagementPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationSetup(databaseTransaction)
	databaseTransaction.enqueueRow(authorizePolicyPublicationSQL, policyPublicationTestRow{err: pgx.ErrNoRows})
	store := beginAuthorizedTestPolicyPublicationStore(t, databaseTransaction)
	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	if _, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime); !errors.Is(err, publication.ErrForbidden) {
		t.Fatalf("Resolve() error = %v, want ErrForbidden", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
}

func TestPolicyPublicationTransactionRequiresManagementCommandWhenConfigured(t *testing.T) {
	t.Parallel()

	command := policyPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationSetup(databaseTransaction)
	store := beginAuthorizedTestPolicyPublicationStore(t, databaseTransaction)
	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	if _, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime); !errors.Is(err, publication.ErrForbidden) {
		t.Fatalf("Resolve() error = %v, want ErrForbidden", err)
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
