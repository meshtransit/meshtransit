package postgres

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/authorization"
	approval "meshtransit.net/core/internal/domain/policy/approval"
)

func TestPolicyApprovalCatalogReadsAuthorizedExactScopeSnapshot(t *testing.T) {
	t.Parallel()

	binding := policyApprovalBindingFixture(t)
	requestID, _ := approval.ParseRequestID(policyApprovalIDValue(901))
	transaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(transaction)
	enqueuePolicyApprovalAuthorization(transaction)
	encoded := policyApprovalCatalogRecordJSON(t, requestID.String(), binding)
	transaction.enqueueRow(readPolicyApprovalCatalogSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = encoded
			return nil
		},
	})
	database := &fakePolicyApprovalDatabase{transactions: []*fakePolicyApprovalTransaction{transaction}}
	store := testPolicyApprovalStore(t, database)
	session := policyApprovalSessionFixture(t, 401, 601)

	value, err := store.ReadApprovalRequest(
		t.Context(), session, binding.Scope(), requestID,
	)
	if err != nil || !value.IsValid() || value.RequestID() != requestID ||
		!value.Binding().Equal(binding) {
		t.Fatalf("ReadApprovalRequest() = (%+v, %v)", value, err)
	}
	if len(database.readOnly) != 1 || database.readOnly[0] || transaction.commitCalls != 1 ||
		transaction.rollbackCalls != 0 || len(transaction.calls) != 4 {
		t.Fatalf("read-only/calls/commit/rollback = %+v/%d/%d/%d", database.readOnly, len(transaction.calls), transaction.commitCalls, transaction.rollbackCalls)
	}
	authorizationCall := transaction.calls[2]
	if authorizationCall.query != authorizePolicyApprovalSQL ||
		authorizationCall.arguments[11] != string(authorization.PermissionPolicyApprove) {
		t.Fatalf("authorization call = %+v", authorizationCall)
	}
	if transaction.calls[3].query != readPolicyApprovalCatalogSQL ||
		transaction.calls[3].arguments[0] != requestID.String() {
		t.Fatalf("read call = %+v", transaction.calls[3])
	}
}

func TestPolicyApprovalCatalogListsBoundedKeysetPage(t *testing.T) {
	t.Parallel()

	binding := policyApprovalBindingFixture(t)
	first, _ := approval.ParseRequestID(policyApprovalIDValue(901))
	second, _ := approval.ParseRequestID(policyApprovalIDValue(902))
	transaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(transaction)
	enqueuePolicyApprovalAuthorization(transaction)
	records := []json.RawMessage{
		json.RawMessage(policyApprovalCatalogRecordJSON(t, first.String(), binding)),
		json.RawMessage(policyApprovalCatalogRecordJSON(t, second.String(), binding)),
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	transaction.enqueueRow(listPolicyApprovalCatalogSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = string(encoded)
			return nil
		},
	})
	database := &fakePolicyApprovalDatabase{transactions: []*fakePolicyApprovalTransaction{transaction}}
	store := testPolicyApprovalStore(t, database)
	values, err := store.ListApprovalRequests(
		t.Context(), policyApprovalSessionFixture(t, 401, 601), binding.Scope(),
		approval.StatePending, first, 2,
	)
	if err != nil || len(values) != 2 || values[0].RequestID() != first || values[1].RequestID() != second {
		t.Fatalf("ListApprovalRequests() = (%+v, %v)", values, err)
	}
	if len(database.readOnly) != 1 || database.readOnly[0] || transaction.commitCalls != 1 ||
		transaction.rollbackCalls != 0 {
		t.Fatalf(
			"transaction mode/commit/rollback = %+v/%d/%d",
			database.readOnly,
			transaction.commitCalls,
			transaction.rollbackCalls,
		)
	}
	call := transaction.calls[3]
	if call.query != listPolicyApprovalCatalogSQL || call.arguments[0] != first.String() ||
		call.arguments[1] != approval.StatePending.String() || call.arguments[2] != 2 {
		t.Fatalf("list call = %+v", call)
	}
}

func TestPolicyApprovalCatalogConcealsAbsentRequest(t *testing.T) {
	t.Parallel()

	binding := policyApprovalBindingFixture(t)
	requestID, _ := approval.ParseRequestID(policyApprovalIDValue(901))
	transaction := newFakePolicyApprovalTransaction()
	enqueuePolicyApprovalSetup(transaction)
	enqueuePolicyApprovalAuthorization(transaction)
	transaction.enqueueRow(readPolicyApprovalCatalogSQL, policyApprovalTestRow{err: pgx.ErrNoRows})
	database := &fakePolicyApprovalDatabase{transactions: []*fakePolicyApprovalTransaction{transaction}}
	store := testPolicyApprovalStore(t, database)
	_, err := store.ReadApprovalRequest(
		t.Context(), policyApprovalSessionFixture(t, 401, 601), binding.Scope(),
		requestID,
	)
	if !errors.Is(err, approval.ErrRequestNotFound) || transaction.commitCalls != 0 ||
		transaction.rollbackCalls != 1 {
		t.Fatalf("error/commit/rollback = %v/%d/%d", err, transaction.commitCalls, transaction.rollbackCalls)
	}
}

func policyApprovalCatalogRecordJSON(
	t *testing.T,
	requestID string,
	binding approval.Binding,
) string {
	t.Helper()
	candidate := binding.CandidateSemanticHash().Bytes()
	impact := binding.ImpactHash().Bytes()
	record := policyApprovalCatalogRecord{
		RequestID: requestID, ProposerPrincipalID: policyApprovalIDValue(401),
		ProposalReason: "reviewed simulation", State: approval.StatePending.String(),
		RequestVersion: 1, Baseline: policyApprovalVectorValues(binding.BaselineVector()),
		Proposed:              policyApprovalVectorValues(binding.ProposedVector()),
		CandidateSemanticHash: hex.EncodeToString(candidate[:]),
		CompilerFormatVersion: binding.CompilerFormatVersion(),
		ImpactHash:            hex.EncodeToString(impact[:]),
		CreatedAt:             policyApprovalTestTime(),
		ExpiresAt:             policyApprovalTestTime().Add(approval.RequestLifetime),
		UpdatedAt:             policyApprovalTestTime(),
	}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
