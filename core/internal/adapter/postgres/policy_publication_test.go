package postgres

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/guardrail"
	publication "meshtransit.net/core/internal/domain/policy/publication"
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
		scaledPolicyPublicationGrantedSQL,
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
		scaledPolicyPublicationGrantedSQL,
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

func TestPolicyPublicationTransactionRevalidatesAndPersistsResourceGroupDestination(t *testing.T) {
	t.Parallel()

	command := policyResourceGroupPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	enqueuePolicyResourceGroupPublicationApply(databaseTransaction, 6, 2)
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
		scaledPolicyPublicationGrantedSQL,
		publishCompiledPolicySQL,
		attachPolicyResourceGroupDestinationsSQL,
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
	if len(rules) != 1 || rules[0].DestinationResourceGroupPublicID == "" ||
		rules[0].DestinationResourceGroupVersion != 2 ||
		rules[0].DestinationGroupDefinitionVersion != 2 ||
		rules[0].DestinationGroupRevision != 8 ||
		len(rules[0].DestinationResourceGroupSemanticHash) != 64 ||
		rules[0].DestinationGroupMemberResourcePublicID == "" ||
		rules[0].DestinationGroupMemberResourceVersion != 3 ||
		rules[0].DestinationGroupMemberTargetGeneration != 2 ||
		rules[0].DestinationGroupMemberInventoryRevision != 7 ||
		len(rules[0].DestinationGroupMemberResourceSemanticHash) != 64 {
		t.Fatalf("published Resource Group rules = %+v, want exact pinned provenance", rules)
	}
}

func TestPolicyPublicationTransactionPublishesImportedResourceAtomically(t *testing.T) {
	t.Parallel()

	command := policyImportedResourcePublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	enqueuePolicyPublicationApply(databaseTransaction, 6, 2)
	enqueueActiveGuardrails(databaseTransaction, "[]")
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
		activeWorkspaceGuardrailsSQL,
		importedResourceProviderGuardrailsSQL,
		setPolicyPublicationChangeSQL,
		scaledPolicyPublicationGrantedSQL,
		publishCompiledPolicySQL,
		appendPolicyPublicationEvidenceSQL,
	}
	if got := policyPublicationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("database call order mismatch\ngot:  %#v\nwant: %#v", got, wantCalls)
	}
	publishCall := findPolicyPublicationCall(t, databaseTransaction.calls, publishCompiledPolicySQL)
	if publishCall.arguments[3] != 4 {
		t.Fatalf("compiler format = %v, want 4", publishCall.arguments[3])
	}
	var rules []policyPublicationRulePayload
	if err := json.Unmarshal(publishCall.arguments[5].([]byte), &rules); err != nil {
		t.Fatalf("decode published rules: %v", err)
	}
	if len(rules) != 1 || rules[0].DestinationNodePublicID != "" ||
		rules[0].DestinationImportedResourcePublicID == "" ||
		rules[0].DestinationTrustContractPublicID == "" ||
		rules[0].DestinationResourceExportPublicID == "" ||
		rules[0].DestinationProviderResourcePublicID == "" ||
		rules[0].DestinationImportedResourceVersion != 2 ||
		rules[0].DestinationTrustContractVersion != 2 ||
		len(rules[0].DestinationProviderResourceSemanticHash) != 64 ||
		len(rules[0].DestinationConstraintHash) != 64 {
		t.Fatalf("published Imported Resource rules = %+v", rules)
	}
	var rawRules []map[string]json.RawMessage
	if err := json.Unmarshal(publishCall.arguments[5].([]byte), &rawRules); err != nil {
		t.Fatal(err)
	}
	if _, found := rawRules[0]["destination_node_public_id"]; found {
		t.Fatal("Imported Resource SQL payload must omit the local destination UUID instead of sending an empty string")
	}
	auditCall := findPolicyPublicationCall(t, databaseTransaction.calls, appendPolicyPublicationEvidenceSQL)
	var auditEvidence policyPublicationAuditPayload
	if err := json.Unmarshal(auditCall.arguments[len(auditCall.arguments)-2].([]byte), &auditEvidence); err != nil {
		t.Fatal(err)
	}
	if auditEvidence.RuleCount != 1 {
		t.Fatal("policy publication audit omitted Imported Resource rule count")
	}
}

const externalSharingGuardrail = `[{"guardrail_id":"01890f00-0000-7000-8000-00000000e001",
"kind":"external_sharing","name":"No external access","description":"","mode":"enforce",
"params":{"direction":"incoming","networks":[],"allowed_workspaces":[]},"version":1,
"created_at":"2026-10-07T00:00:00Z","updated_at":"2026-10-07T00:00:00Z"}]`

// An enforced guardrail refuses a new rule that reaches a Device shared from
// another Workspace, before anything is published; a path the active release
// already opens is not blocked retroactively, only recorded.
func TestPolicyPublicationTransactionAppliesGuardrailsToNewPathsOnly(t *testing.T) {
	t.Parallel()

	for _, existing := range []bool{false, true} {
		command := policyImportedResourcePublicationCommandFixture(t)
		databaseTransaction := newFakePolicyPublicationTransaction()
		enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
		enqueuePolicyPublicationApply(databaseTransaction, 6, 2)
		enqueueActiveGuardrails(databaseTransaction, externalSharingGuardrail)
		paths := "[]"
		if existing {
			destination := command.Candidate().ImportedResourceDestinations()[0]
			paths = `["` + destination.SourceNodeID().String() + ":" +
				destination.Resolution().ImportedResourceID().String() + `"]`
		}
		databaseTransaction.enqueueRow(activeReleaseImportedPathsSQL, policyPublicationTestRow{
			scan: func(destinations ...any) error {
				*destinations[0].(*string) = paths
				return nil
			}})
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
		if existing {
			if err != nil {
				t.Fatalf("Apply() on an existing path error = %v", err)
			}
			auditCall := findPolicyPublicationCall(t, databaseTransaction.calls, appendPolicyPublicationEvidenceSQL)
			var evidence policyPublicationAuditPayload
			if err := json.Unmarshal(auditCall.arguments[len(auditCall.arguments)-2].([]byte), &evidence); err != nil {
				t.Fatal(err)
			}
			if len(evidence.GuardrailFindings) != 1 || evidence.GuardrailFindings[0].Mode != "enforce" {
				t.Fatalf("existing-path findings = %+v, want the enforced guardrail recorded", evidence.GuardrailFindings)
			}
			continue
		}
		var violation *guardrail.ViolationError
		if !errors.As(err, &violation) || len(violation.Findings) != 1 ||
			violation.Findings[0].Reason != guardrail.ReasonExternalSharing {
			t.Fatalf("Apply() error = %v, want an external-sharing guardrail violation", err)
		}
		for _, call := range databaseTransaction.calls {
			if call.query == publishCompiledPolicySQL || call.query == appendPolicyPublicationEvidenceSQL {
				t.Fatalf("blocked publication still ran %q", call.query)
			}
		}
	}
}

func enqueueActiveGuardrails(transaction *fakePolicyPublicationTransaction, encoded string) {
	transaction.enqueueRow(activeWorkspaceGuardrailsSQL, policyPublicationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = encoded
		return nil
	}})
	// The Imported Resource fixture's provider Workspace, with no guardrail.
	enqueueProviderGuardrails(transaction, `[{"workspace_id":"01890f00-0000-7000-8000-000000000102","guardrails":[]}]`)
}

func enqueueProviderGuardrails(transaction *fakePolicyPublicationTransaction, encoded string) {
	transaction.enqueueRow(importedResourceProviderGuardrailsSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = encoded
			return nil
		}})
}

// A provider the reader does not report is never taken to have no guardrail:
// the publication fails before anything is published.
func TestPolicyPublicationTransactionFailsClosedOnUnknownProvider(t *testing.T) {
	t.Parallel()
	command := policyImportedResourcePublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	enqueuePolicyPublicationApply(databaseTransaction, 6, 2)
	databaseTransaction.enqueueRow(activeWorkspaceGuardrailsSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = "[]"
			return nil
		}})
	enqueueProviderGuardrails(databaseTransaction, "[]")
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
	if _, err := transaction.Apply(t.Context(), policyPublicationChangeFixture(t, command, resolution)); err == nil {
		t.Fatal("published although the provider's guardrails were unknown")
	}
	for _, call := range databaseTransaction.calls {
		if call.query == publishCompiledPolicySQL {
			t.Fatal("published although the provider's guardrails were unknown")
		}
	}
}

// The provider of an Imported Resource keeps its guardrails private: an
// enforced one refuses a new path with a refusal that names nothing, even
// when this Workspace has no guardrail; a path already open is not blocked,
// and the provider's findings never reach this Network's evidence.
func TestPolicyPublicationTransactionAppliesProviderGuardrailsToNewPathsOnly(t *testing.T) {
	t.Parallel()

	for _, existing := range []bool{false, true} {
		command := policyImportedResourcePublicationCommandFixture(t)
		destination := command.Candidate().ImportedResourceDestinations()[0]
		provider := destination.Resolution().ProviderScope()
		databaseTransaction := newFakePolicyPublicationTransaction()
		enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
		enqueuePolicyPublicationApply(databaseTransaction, 6, 2)
		databaseTransaction.enqueueRow(activeWorkspaceGuardrailsSQL, policyPublicationTestRow{
			scan: func(destinations ...any) error {
				*destinations[0].(*string) = "[]"
				return nil
			}})
		providerLock := `[{"guardrail_id":"01890f00-0000-7000-8000-00000000e002",
"kind":"network_sharing","name":"Provider secret lock","description":"","mode":"enforce",
"params":{"direction":"outgoing","networks":["` + provider.NetworkID().String() + `"]},"version":1,
"created_at":"2026-10-07T00:00:00Z","updated_at":"2026-10-07T00:00:00Z"}]`
		enqueueProviderGuardrails(databaseTransaction, `[{"workspace_id":"`+
			provider.WorkspaceID().String()+`","guardrails":`+providerLock+`}]`)
		paths := "[]"
		if existing {
			paths = `["` + destination.SourceNodeID().String() + ":" +
				destination.Resolution().ImportedResourceID().String() + `"]`
		}
		databaseTransaction.enqueueRow(activeReleaseImportedPathsSQL, policyPublicationTestRow{
			scan: func(destinations ...any) error {
				*destinations[0].(*string) = paths
				return nil
			}})
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
		if existing {
			if err != nil {
				t.Fatalf("Apply() on an existing path error = %v", err)
			}
			auditCall := findPolicyPublicationCall(t, databaseTransaction.calls, appendPolicyPublicationEvidenceSQL)
			if strings.Contains(string(auditCall.arguments[len(auditCall.arguments)-2].([]byte)), "Provider secret lock") {
				t.Fatal("the provider's guardrail reached the consumer's evidence")
			}
			continue
		}
		var counterpart *guardrail.CounterpartViolationError
		var violation *guardrail.ViolationError
		if !errors.As(err, &counterpart) || errors.As(err, &violation) {
			t.Fatalf("Apply() error = %v, want a refusal that names no provider guardrail", err)
		}
		for _, call := range databaseTransaction.calls {
			if call.query == publishCompiledPolicySQL || call.query == appendPolicyPublicationEvidenceSQL {
				t.Fatalf("blocked publication still ran %q", call.query)
			}
		}
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

func TestPolicyPublicationTransactionRequiresApprovalEvidenceInProductionMode(t *testing.T) {
	t.Parallel()

	command := policyManagementPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationSetup(databaseTransaction)
	enqueuePolicyPublicationAuthorization(databaseTransaction)
	store := beginApprovalRequiredTestPolicyPublicationStore(t, databaseTransaction)

	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	if _, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime); !errors.Is(
		err,
		publication.ErrApprovalRequired,
	) {
		t.Fatalf("Resolve() error = %v, want ErrApprovalRequired", err)
	}
	if err := transaction.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	wantCalls := []string{
		configurePolicyPublicationTransactionSQL,
		setPolicyPublicationScopeSQL,
		authorizePolicyPublicationSQL,
	}
	if got := policyPublicationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("database call order mismatch\ngot:  %#v\nwant: %#v", got, wantCalls)
	}
}

func TestPolicyPublicationTransactionConsumesApprovalWithReleaseAuditAndOutbox(t *testing.T) {
	t.Parallel()

	command := policyApprovedManagementPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationAuthorization(databaseTransaction)
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	enqueuePolicyPublicationApproval(t, databaseTransaction, command, 5, 1)
	enqueueApprovedPolicyPublicationApply(databaseTransaction, 6, 2)
	store := beginApprovalRequiredTestPolicyPublicationStore(t, databaseTransaction)

	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	resolution, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !resolution.ApprovalGate().IsValid() ||
		resolution.ApprovalGate().EvidenceID() != command.ApprovalEvidenceID() ||
		!transaction.approvalAuthorization.isValid() {
		t.Fatalf("approval resolution = %+v authority=%+v", resolution, transaction.approvalAuthorization)
	}
	change := approvedPolicyPublicationChangeFixture(t, command, resolution)
	result, err := transaction.Apply(t.Context(), change)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.NetworkRevision() != 6 || result.PolicyRevision() != 2 {
		t.Fatalf("Apply() result = %+v, want revisions 6/2", result)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	wantCalls := []string{
		configurePolicyPublicationTransactionSQL,
		setPolicyPublicationScopeSQL,
		authorizePolicyPublicationSQL,
		lockPolicyPublicationRevisionSQL,
		lockActivePolicyReleaseSQL,
		lockPolicyPublicationApprovalSQL,
		authorizePolicyPublicationSQL,
		lockPolicyPublicationAuditStreamSQL,
		setPolicyPublicationChangeSQL,
		scaledPolicyPublicationGrantedSQL,
		publishCompiledPolicySQL,
		consumePolicyPublicationApprovalSQL,
		appendPolicyPublicationEvidenceSQL,
	}
	if got := policyPublicationCallQueries(databaseTransaction.calls); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("database call order mismatch\ngot:  %#v\nwant: %#v", got, wantCalls)
	}
	permissions := make([]string, 0, 2)
	for _, call := range databaseTransaction.calls {
		if call.query == authorizePolicyPublicationSQL {
			permissions = append(permissions, call.arguments[11].(string))
		}
	}
	if !reflect.DeepEqual(permissions, []string{"policy.publish", "policy.approve"}) {
		t.Fatalf("authorization permissions = %v", permissions)
	}
	consumeCall := findPolicyPublicationCall(
		t,
		databaseTransaction.calls,
		consumePolicyPublicationApprovalSQL,
	)
	if len(consumeCall.arguments) != 6 ||
		consumeCall.arguments[0] != command.ApprovalEvidenceID().String() ||
		consumeCall.arguments[1] != change.MutationIDs().ReleaseID().String() ||
		consumeCall.arguments[3] != command.Candidate().CompilerFormatVersion() ||
		consumeCall.arguments[5] != policyPublicationTestTime {
		t.Fatalf("approval consumption arguments = %#v", consumeCall.arguments)
	}
	evidenceCall := findPolicyPublicationCall(
		t,
		databaseTransaction.calls,
		appendPolicyPublicationEvidenceSQL,
	)
	var auditPayload policyPublicationAuditPayload
	if err := json.Unmarshal(evidenceCall.arguments[14].([]byte), &auditPayload); err != nil {
		t.Fatalf("decode audit payload: %v", err)
	}
	if auditPayload.ApprovalEvidenceID != command.ApprovalEvidenceID().String() ||
		auditPayload.ApprovalRequestID == "" || len(auditPayload.ApprovalImpactHash) != 64 ||
		auditPayload.ApprovalBaselineVector == nil ||
		auditPayload.ApprovalProposedVector == nil ||
		auditPayload.ApproverAccountSessionID == "" ||
		auditPayload.ApproverRoleBindingID == "" {
		t.Fatalf("approval audit payload = %+v", auditPayload)
	}
}

func TestPolicyPublicationTransactionRejectsUnavailableApprovalEvidence(t *testing.T) {
	t.Parallel()

	command := policyApprovedManagementPublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationAuthorization(databaseTransaction)
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	databaseTransaction.enqueueRow(
		lockPolicyPublicationApprovalSQL,
		policyPublicationTestRow{err: pgx.ErrNoRows},
	)
	store := beginApprovalRequiredTestPolicyPublicationStore(t, databaseTransaction)
	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	transaction := value.(*policyPublicationTransaction)
	if _, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime); !errors.Is(
		err,
		publication.ErrApprovalUnavailable,
	) {
		t.Fatalf("Resolve() error = %v, want ErrApprovalUnavailable", err)
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
	options = testPolicyPublicationOptions()
	options.ApprovalMode = PolicyPublicationApprovalModeUnknown
	if _, err := newPolicyPublicationStore(
		&fakePolicyPublicationDatabase{},
		options,
		nil,
	); !errors.Is(err, ErrInvalidPolicyPublicationStore) {
		t.Fatalf("newPolicyPublicationStore() unknown approval mode error = %v", err)
	}
	options = testPolicyPublicationOptions()
	options.ApprovalMode = PolicyPublicationApprovalModePublisherAuthorized
	options.AllowTrustedActor = true
	if _, err := newPolicyPublicationStore(&fakePolicyPublicationDatabase{}, options, nil); !errors.Is(err, ErrInvalidPolicyPublicationStore) {
		t.Fatalf("publisher-authorized mode accepted a trusted actor: %v", err)
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

// TestPolicyPublicationTransactionUsesScaledPublishOnceGranted: a policy
// naming Imported Resources publishes through publish_compiled_policy_v2
// (schema 148) once runtime may run it, with the same arguments.
func TestPolicyPublicationTransactionUsesScaledPublishOnceGranted(t *testing.T) {
	t.Parallel()

	command := policyImportedResourcePublicationCommandFixture(t)
	databaseTransaction := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationResolution(t, databaseTransaction, command, 5, 1)
	enqueuePolicyPublicationApply(databaseTransaction, 6, 2)
	// Serve the scaled query with the row the legacy one would have used.
	databaseTransaction.rows[publishScaledCompiledPolicySQL] = databaseTransaction.rows[publishCompiledPolicySQL]
	delete(databaseTransaction.rows, publishCompiledPolicySQL)
	databaseTransaction.enqueueRow(scaledPolicyPublicationGrantedSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*bool) = true
			return nil
		},
	})
	enqueueActiveGuardrails(databaseTransaction, "[]")
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
	if _, err := transaction.Apply(t.Context(), policyPublicationChangeFixture(t, command, resolution)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	calls := policyPublicationCallQueries(databaseTransaction.calls)
	if !slices.Contains(calls, publishScaledCompiledPolicySQL) || slices.Contains(calls, publishCompiledPolicySQL) {
		t.Fatalf("granted publish v2 not used: %v", calls)
	}
	publishCall := findPolicyPublicationCall(t, databaseTransaction.calls, publishScaledCompiledPolicySQL)
	if len(publishCall.arguments) != 6 || publishCall.arguments[3] != 4 {
		t.Fatalf("publish v2 arguments = %v", publishCall.arguments)
	}
}
