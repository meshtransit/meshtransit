package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	approval "github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

type policyApprovalTestCall struct {
	query     string
	arguments []any
}

type fakePolicyApprovalDatabase struct {
	transactions []*fakePolicyApprovalTransaction
	readOnly     []bool
	beginErr     error
}

func (database *fakePolicyApprovalDatabase) Begin(
	_ context.Context,
	readOnly bool,
) (policyApprovalDatabaseTransaction, error) {
	database.readOnly = append(database.readOnly, readOnly)
	if database.beginErr != nil {
		return nil, database.beginErr
	}
	if len(database.transactions) == 0 {
		return nil, errors.New("no queued Policy approval transaction")
	}
	transaction := database.transactions[0]
	database.transactions = database.transactions[1:]
	return transaction, nil
}

type fakePolicyApprovalTransaction struct {
	rows          map[string][]policyApprovalRow
	execErrors    map[string][]error
	calls         []policyApprovalTestCall
	commitErr     error
	rollbackErr   error
	commitCalls   int
	rollbackCalls int
}

func newFakePolicyApprovalTransaction() *fakePolicyApprovalTransaction {
	return &fakePolicyApprovalTransaction{
		rows:       make(map[string][]policyApprovalRow),
		execErrors: make(map[string][]error),
	}
}

func (transaction *fakePolicyApprovalTransaction) Exec(
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

func (transaction *fakePolicyApprovalTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) policyApprovalRow {
	transaction.record(query, arguments)
	queued := transaction.rows[query]
	if len(queued) == 0 {
		return policyApprovalTestRow{err: fmt.Errorf("unexpected Policy approval query: %s", query)}
	}
	transaction.rows[query] = queued[1:]
	return queued[0]
}

func (transaction *fakePolicyApprovalTransaction) Commit(context.Context) error {
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakePolicyApprovalTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakePolicyApprovalTransaction) enqueueRow(
	query string,
	row policyApprovalRow,
) {
	transaction.rows[query] = append(transaction.rows[query], row)
}

func (transaction *fakePolicyApprovalTransaction) record(query string, arguments []any) {
	transaction.calls = append(transaction.calls, policyApprovalTestCall{
		query: query, arguments: append([]any(nil), arguments...),
	})
}

type policyApprovalTestRow struct {
	scan func(...any) error
	err  error
}

func (row policyApprovalTestRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if row.scan == nil {
		return nil
	}
	return row.scan(destinations...)
}

func testPolicyApprovalOptions() PolicyApprovalOptions {
	return PolicyApprovalOptions{
		StatementTimeout: 5 * time.Second,
		LockTimeout:      time.Second,
		IdleTimeout:      10 * time.Second,
	}
}

func testPolicyApprovalStore(
	t *testing.T,
	database *fakePolicyApprovalDatabase,
) *PolicyApprovalStore {
	t.Helper()
	store, err := newPolicyApprovalStore(database, testPolicyApprovalOptions(), nil)
	if err != nil {
		t.Fatalf("newPolicyApprovalStore() error = %v", err)
	}
	return store
}

func enqueuePolicyApprovalSetup(transaction *fakePolicyApprovalTransaction) {
	transaction.enqueueRow(setPolicyApprovalScopeSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 101
			*destinations[1].(*int64) = 201
			return nil
		},
	})
}

func enqueuePolicyApprovalAuthorization(transaction *fakePolicyApprovalTransaction) {
	transaction.enqueueRow(authorizePolicyApprovalSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = "01890f00-0000-7000-8000-000000000821"
			*destinations[1].(*string) = "01890f00-0000-7000-8000-000000000822"
			for index, generation := range [...]int64{3, 4, 5, 6} {
				*destinations[index+2].(*int64) = generation
			}
			*destinations[6].(*bool) = false
			*destinations[7].(*time.Time) = policyApprovalTestTime()
			return nil
		},
	})
}

func enqueuePolicyApprovalPendingClaim(
	transaction *fakePolicyApprovalTransaction,
	recordID publicid.ID,
	requestHash [sha256.Size]byte,
	expiresAt time.Time,
) {
	transaction.enqueueRow(claimPolicyApprovalIdempotencySQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = recordID.String()
			*destinations[1].(*[]byte) = append([]byte(nil), requestHash[:]...)
			*destinations[2].(*string) = "pending"
			*destinations[8].(*time.Time) = expiresAt
			*destinations[9].(*bool) = true
			return nil
		},
	})
}

func enqueuePolicyApprovalCompletedClaim(
	transaction *fakePolicyApprovalTransaction,
	recordID publicid.ID,
	requestHash [sha256.Size]byte,
	resultKind string,
	resultID string,
	resultVersion int64,
	networkRevision int64,
	expiresAt time.Time,
) {
	transaction.enqueueRow(claimPolicyApprovalIdempotencySQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = recordID.String()
			*destinations[1].(*[]byte) = append([]byte(nil), requestHash[:]...)
			*destinations[2].(*string) = "completed"
			*destinations[3].(**string) = &resultKind
			*destinations[4].(**string) = &resultID
			*destinations[5].(**int64) = &resultVersion
			*destinations[6].(**int64) = &networkRevision
			*destinations[7].(*[]byte) = []byte(`{}`)
			*destinations[8].(*time.Time) = expiresAt
			*destinations[9].(*bool) = false
			return nil
		},
	})
}

func enqueuePolicyApprovalAuditHead(transaction *fakePolicyApprovalTransaction) {
	transaction.enqueueRow(lockPolicyApprovalAuditStreamSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 3
			*destinations[1].(*int64) = 4
			*destinations[2].(*[]byte) = make([]byte, sha256.Size)
			return nil
		},
	})
}

func enqueuePolicyApprovalEvidenceAppend(transaction *fakePolicyApprovalTransaction) {
	transaction.enqueueRow(appendPolicyApprovalEvidenceSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 4
			return nil
		},
	})
}

func enqueuePolicyApprovalCompletion(
	transaction *fakePolicyApprovalTransaction,
	recordID publicid.ID,
) {
	transaction.enqueueRow(completePolicyApprovalIdempotencySQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = recordID.String()
			return nil
		},
	})
}

func enqueuePolicyApprovalRevision(
	transaction *fakePolicyApprovalTransaction,
	vector accessgraph.RevisionVector,
) {
	transaction.enqueueRow(lockPolicyApprovalRevisionSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			values := policyApprovalVectorValues(vector)
			for index, value := range values {
				*destinations[index].(*int64) = value
			}
			return nil
		},
	})
}

func enqueueLockedPolicyApprovalRequest(
	transaction *fakePolicyApprovalTransaction,
	binding approval.Binding,
	proposer accountsession.Session,
	createdAt time.Time,
) {
	transaction.enqueueRow(lockPolicyApprovalRequestSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 1
			*destinations[1].(*string) = approval.StatePending.String()
			*destinations[2].(*string) = proposer.PrincipalID().String()
			*destinations[3].(*string) = proposer.ID().String()
			assignPolicyApprovalBinding(destinations[4:23], binding)
			*destinations[23].(*time.Time) = createdAt
			*destinations[24].(*time.Time) = createdAt.Add(approval.RequestLifetime)
			return nil
		},
	})
}

func enqueueLoadedPolicyApprovalRequest(
	transaction *fakePolicyApprovalTransaction,
	binding approval.Binding,
	proposer accountsession.Session,
	createdAt time.Time,
) {
	transaction.enqueueRow(loadPolicyApprovalRequestSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = proposer.PrincipalID().String()
			*destinations[1].(*string) = proposer.ID().String()
			assignPolicyApprovalBinding(destinations[2:21], binding)
			*destinations[21].(*time.Time) = createdAt
			*destinations[22].(*time.Time) = createdAt.Add(approval.RequestLifetime)
			return nil
		},
	})
}

func enqueueLoadedPolicyApprovalEvidence(
	transaction *fakePolicyApprovalTransaction,
	binding approval.Binding,
	requestID approval.RequestID,
	proposer accountsession.Session,
	approver accountsession.Session,
	approvedAt time.Time,
	expiresAt time.Time,
) {
	transaction.enqueueRow(loadPolicyApprovalEvidenceSQL, policyApprovalTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = requestID.String()
			*destinations[1].(*string) = proposer.PrincipalID().String()
			*destinations[2].(*string) = proposer.ID().String()
			*destinations[3].(*string) = approver.PrincipalID().String()
			*destinations[4].(*string) = approver.ID().String()
			assignPolicyApprovalBinding(destinations[5:24], binding)
			*destinations[24].(*int64) = 2
			*destinations[25].(*int64) = 1
			*destinations[26].(*time.Time) = approvedAt
			*destinations[27].(*time.Time) = expiresAt
			return nil
		},
	})
}

func assignPolicyApprovalBinding(destinations []any, binding approval.Binding) {
	baseline := policyApprovalVectorValues(binding.BaselineVector())
	proposed := policyApprovalVectorValues(binding.ProposedVector())
	for index, value := range baseline {
		*destinations[index].(*int64) = value
	}
	for index, value := range proposed {
		*destinations[index+8].(*int64) = value
	}
	candidateHash := binding.CandidateSemanticHash().Bytes()
	impactHash := binding.ImpactHash().Bytes()
	*destinations[16].(*[]byte) = append([]byte(nil), candidateHash[:]...)
	*destinations[17].(*int) = binding.CompilerFormatVersion()
	*destinations[18].(*[]byte) = append([]byte(nil), impactHash[:]...)
}

func policyApprovalVectorValues(vector accessgraph.RevisionVector) [8]int64 {
	return [8]int64{
		vector.NetworkRevision(), vector.InventoryRevision(), vector.GroupRevision(),
		vector.PolicyRevision(), vector.DNSRevision(), vector.RouteRevision(),
		vector.SharingRevision(), vector.IsolationGeneration(),
	}
}

func policyApprovalBindingFixture(t *testing.T) approval.Binding {
	t.Helper()
	baseline, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: 11, InventoryRevision: 7, GroupRevision: 8, PolicyRevision: 1,
		DNSRevision: 2, RouteRevision: 3, SharingRevision: 4, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := baseline.NextPolicy()
	if err != nil {
		t.Fatal(err)
	}
	candidateValue := sha256.Sum256([]byte("Policy approval candidate"))
	candidate, err := publication.NewSemanticHash(candidateValue)
	if err != nil {
		t.Fatal(err)
	}
	impactValue := sha256.Sum256([]byte("Policy approval impact"))
	impact, err := simulation.NewImpactHash(impactValue)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := approval.NewBinding(approval.BindingParams{
		Scope: postgresPolicySimulationScope(t), BaselineVector: baseline,
		ProposedVector: proposed, CandidateSemanticHash: candidate,
		CompilerFormatVersion: 1, ImpactHash: impact,
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func policyApprovalSessionFixture(
	t *testing.T,
	principalSequence int,
	sessionSequence int,
) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	principalID, err := identity.ParsePrincipalID(policyApprovalIDValue(principalSequence))
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := accountsession.ParseID(policyApprovalIDValue(sessionSequence))
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(
		policyApprovalIDValue(principalSequence + 200),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := policyApprovalTestTime()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: postgresPolicySimulationScope(t).WorkspaceID(),
		HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Minute),
		ACR: "urn:meshtransit:test", AMR: []string{"mfa"}, Version: 1,
		PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func policyApprovalRequestCommandFixture(
	t *testing.T,
	binding approval.Binding,
	proposer accountsession.Session,
) approval.RequestCommand {
	t.Helper()
	reason, err := approval.NewAuditReason("request independent Policy approval")
	if err != nil {
		t.Fatal(err)
	}
	command, err := approval.NewRequestCommand(
		binding, proposer, reason, policyApprovalProofFixture(t, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func policyApprovalCommandFixture(
	t *testing.T,
	binding approval.Binding,
	approver accountsession.Session,
	requestID approval.RequestID,
) approval.Command {
	t.Helper()
	reason, err := approval.NewAuditReason("approve unchanged Policy impact")
	if err != nil {
		t.Fatal(err)
	}
	command, err := approval.NewCommand(approval.CommandParams{
		Scope: binding.Scope(), RequestID: requestID, ExpectedRequestVersion: 1,
		CandidateSemanticHash: binding.CandidateSemanticHash(), ImpactHash: binding.ImpactHash(),
		AccountSession: approver, AuditReason: reason,
		IdempotencyEvidence: policyApprovalProofFixture(t, 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func policyApprovalRequestMutationIDsFixture(t *testing.T) approval.RequestMutationIDs {
	t.Helper()
	requestID, err := approval.ParseRequestID(policyApprovalIDValue(920))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := approval.NewRequestMutationIDs(approval.RequestMutationIDParams{
		RequestID: requestID, ChangeID: policyApprovalPublicIDFixture(t, 921),
		IdempotencyRecordID: policyApprovalPublicIDFixture(t, 922),
		AuditEventID:        policyApprovalPublicIDFixture(t, 923),
		OutboxEventID:       policyApprovalPublicIDFixture(t, 924),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func policyApprovalMutationIDsFixture(t *testing.T) approval.MutationIDs {
	t.Helper()
	evidenceID, err := approval.ParseEvidenceID(policyApprovalIDValue(930))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := approval.NewMutationIDs(approval.MutationIDParams{
		EvidenceID: evidenceID, ChangeID: policyApprovalPublicIDFixture(t, 931),
		IdempotencyRecordID: policyApprovalPublicIDFixture(t, 932),
		AuditEventID:        policyApprovalPublicIDFixture(t, 933),
		OutboxEventID:       policyApprovalPublicIDFixture(t, 934),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func policyApprovalProofFixture(t *testing.T, marker byte) idempotency.Proof {
	t.Helper()
	var digest [sha256.Size]byte
	digest[0] = marker
	proof, err := idempotency.NewProof("approval-key-v1", digest)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func policyApprovalPublicIDFixture(t *testing.T, sequence int) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(policyApprovalIDValue(sequence))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func policyApprovalIDValue(sequence int) string {
	return fmt.Sprintf("01890f00-0000-7000-8000-%012d", sequence)
}

func policyApprovalTestTime() time.Time {
	return time.Date(2026, time.September, 29, 15, 0, 0, 0, time.UTC)
}
