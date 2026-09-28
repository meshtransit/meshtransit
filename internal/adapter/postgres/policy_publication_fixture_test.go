package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

type policyPublicationTestCall struct {
	query     string
	arguments []any
}

type fakePolicyPublicationDatabase struct {
	transactions []*fakePolicyPublicationTransaction
	readOnly     []bool
	beginErr     error
}

func (database *fakePolicyPublicationDatabase) Begin(
	_ context.Context,
	readOnly bool,
) (policyPublicationDatabaseTransaction, error) {
	database.readOnly = append(database.readOnly, readOnly)
	if database.beginErr != nil {
		return nil, database.beginErr
	}
	if len(database.transactions) == 0 {
		return nil, errors.New("no queued policy publication transaction")
	}
	transaction := database.transactions[0]
	database.transactions = database.transactions[1:]
	return transaction, nil
}

type fakePolicyPublicationTransaction struct {
	rows          map[string][]policyPublicationRow
	execErrors    map[string][]error
	calls         []policyPublicationTestCall
	commitErr     error
	rollbackErr   error
	commitCalls   int
	rollbackCalls int
}

func newFakePolicyPublicationTransaction() *fakePolicyPublicationTransaction {
	return &fakePolicyPublicationTransaction{
		rows:       make(map[string][]policyPublicationRow),
		execErrors: make(map[string][]error),
	}
}

func (transaction *fakePolicyPublicationTransaction) Exec(
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

func (transaction *fakePolicyPublicationTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) policyPublicationRow {
	transaction.record(query, arguments)
	queued := transaction.rows[query]
	if len(queued) == 0 {
		return policyPublicationTestRow{err: fmt.Errorf("unexpected policy publication query: %s", query)}
	}
	transaction.rows[query] = queued[1:]
	return queued[0]
}

func (transaction *fakePolicyPublicationTransaction) Commit(context.Context) error {
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakePolicyPublicationTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakePolicyPublicationTransaction) enqueueRow(
	query string,
	row policyPublicationRow,
) {
	transaction.rows[query] = append(transaction.rows[query], row)
}

func (transaction *fakePolicyPublicationTransaction) record(query string, arguments []any) {
	transaction.calls = append(transaction.calls, policyPublicationTestCall{
		query:     query,
		arguments: append([]any(nil), arguments...),
	})
}

type policyPublicationTestRow struct {
	scan func(...any) error
	err  error
}

func (row policyPublicationTestRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if row.scan == nil {
		return nil
	}
	return row.scan(destinations...)
}

func testPolicyPublicationOptions() PolicyPublicationOptions {
	return PolicyPublicationOptions{
		StatementTimeout:  5 * time.Second,
		LockTimeout:       time.Second,
		IdleTimeout:       10 * time.Second,
		AllowTrustedActor: true,
	}
}

func beginTestPolicyPublicationStore(
	t *testing.T,
	databaseTransaction *fakePolicyPublicationTransaction,
) *PolicyPublicationStore {
	t.Helper()
	store, err := newPolicyPublicationStore(
		&fakePolicyPublicationDatabase{transactions: []*fakePolicyPublicationTransaction{
			databaseTransaction,
		}},
		testPolicyPublicationOptions(),
		nil,
	)
	if err != nil {
		t.Fatalf("newPolicyPublicationStore() error = %v", err)
	}
	return store
}

func beginAuthorizedTestPolicyPublicationStore(
	t *testing.T,
	databaseTransaction *fakePolicyPublicationTransaction,
) *PolicyPublicationStore {
	t.Helper()
	options := testPolicyPublicationOptions()
	options.AllowTrustedActor = false
	store, err := newPolicyPublicationStore(
		&fakePolicyPublicationDatabase{transactions: []*fakePolicyPublicationTransaction{
			databaseTransaction,
		}},
		options,
		nil,
	)
	if err != nil {
		t.Fatalf("newPolicyPublicationStore() error = %v", err)
	}
	return store
}

func enqueuePolicyPublicationAuthorization(
	transaction *fakePolicyPublicationTransaction,
) {
	transaction.enqueueRow(authorizePolicyPublicationSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = "01890f00-0000-7000-8000-000000000821"
			*destinations[1].(*string) = "01890f00-0000-7000-8000-000000000822"
			for index, generation := range [...]int64{3, 4, 5, 6} {
				*destinations[index+2].(*int64) = generation
			}
			*destinations[6].(*bool) = false
			*destinations[7].(*time.Time) = policyPublicationTestTime
			return nil
		},
	})
}

func enqueuePolicyPublicationSetup(transaction *fakePolicyPublicationTransaction) {
	transaction.enqueueRow(setPolicyPublicationScopeSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 101
			*destinations[1].(*int64) = 201
			return nil
		},
	})
}

func enqueuePolicyPublicationResolution(
	t *testing.T,
	transaction *fakePolicyPublicationTransaction,
	command publication.Command,
	networkRevision int64,
	policyRevision int64,
) {
	t.Helper()
	enqueuePolicyPublicationSetup(transaction)
	transaction.enqueueRow(lockPolicyPublicationRevisionSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			for index, value := range [...]int64{networkRevision, 1, 1, policyRevision, 1, 1, 1, 1} {
				*destinations[index].(*int64) = value
			}
			return nil
		},
	})
	if policyRevision == 1 {
		transaction.enqueueRow(lockActivePolicyReleaseSQL, policyPublicationTestRow{err: pgx.ErrNoRows})
	} else {
		hash := command.Candidate().SemanticHash().Bytes()
		transaction.enqueueRow(lockActivePolicyReleaseSQL, policyPublicationTestRow{
			scan: func(destinations ...any) error {
				*destinations[0].(*string) = "01890f00-0000-7000-8000-000000000901"
				*destinations[1].(*int64) = policyRevision
				*destinations[2].(*[]byte) = append([]byte(nil), hash[:]...)
				return nil
			},
		})
	}
	transaction.enqueueRow(lockPolicyPublicationAuditStreamSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 3
			*destinations[1].(*int64) = 4
			*destinations[2].(*[]byte) = make([]byte, 32)
			return nil
		},
	})
}

func enqueuePolicyPublicationApply(
	transaction *fakePolicyPublicationTransaction,
	networkRevision int64,
	policyRevision int64,
) {
	transaction.enqueueRow(publishCompiledPolicySQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = networkRevision
			*destinations[1].(*int64) = policyRevision
			*destinations[2].(*int64) = 1
			return nil
		},
	})
	transaction.enqueueRow(appendPolicyPublicationEvidenceSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 4
			return nil
		},
	})
}

func enqueuePolicyResourcePublicationApply(
	transaction *fakePolicyPublicationTransaction,
	networkRevision int64,
	policyRevision int64,
) {
	transaction.enqueueRow(publishCompiledPolicySQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = networkRevision
			*destinations[1].(*int64) = policyRevision
			*destinations[2].(*int64) = 1
			return nil
		},
	})
	transaction.enqueueRow(attachPolicyResourceDestinationsSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int) = 1
			return nil
		},
	})
	transaction.enqueueRow(appendPolicyPublicationEvidenceSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 4
			return nil
		},
	})
}

func policyPublicationCommandFixture(t *testing.T) publication.Command {
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
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	sourceID, err := node.ParseID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("node.ParseID(source) error = %v", err)
	}
	destinationID, err := node.ParseID("01890f00-0000-7000-8000-000000000702")
	if err != nil {
		t.Fatalf("node.ParseID(destination) error = %v", err)
	}
	portRange, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatalf("policy.NewPortRange() error = %v", err)
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                    ruleID,
		Scope:                 scope,
		SourceNodeID:          sourceID,
		DestinationNodeID:     destinationID,
		Protocol:              policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{portRange},
	})
	if err != nil {
		t.Fatalf("policy.NewRule() error = %v", err)
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    scope,
		Revision: 2,
		Rules:    []policy.Rule{rule},
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	candidate, err := publication.NewCandidate(snapshot, 1)
	if err != nil {
		t.Fatalf("publication.NewCandidate() error = %v", err)
	}
	actor, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	reason, err := publication.NewAuditReason("phase 1 policy")
	if err != nil {
		t.Fatalf("publication.NewAuditReason() error = %v", err)
	}
	command, err := publication.NewCommand(publication.CommandParams{
		Candidate:          candidate,
		BasePolicyRevision: 1,
		ActorPrincipalID:   actor,
		AuditReason:        reason,
	})
	if err != nil {
		t.Fatalf("publication.NewCommand() error = %v", err)
	}
	return command
}

func policyManagementPublicationCommandFixture(t *testing.T) publication.Command {
	t.Helper()
	trusted := policyPublicationCommandFixture(t)
	command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: trusted.Candidate(), BasePolicyRevision: trusted.BasePolicyRevision(),
		AccountSession: deviceRevocationAccountSessionFixture(
			t,
			trusted.ActorPrincipalID(),
			trusted.Candidate().Snapshot().Scope().WorkspaceID(),
		),
		AuditReason: trusted.AuditReason(),
	})
	if err != nil {
		t.Fatalf("publication.NewManagementCommand() error = %v", err)
	}
	return command
}

func policyResourcePublicationCommandFixture(t *testing.T) publication.Command {
	t.Helper()
	trusted := policyPublicationCommandFixture(t)
	rule := trusted.Candidate().Snapshot().Rules()[0]
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000921")
	if err != nil {
		t.Fatalf("resource.ParseID() error = %v", err)
	}
	hashValue := sha256.Sum256([]byte("synthetic policy Resource"))
	resourceHash, err := resource.NewSemanticHash(hashValue)
	if err != nil {
		t.Fatalf("resource.NewSemanticHash() error = %v", err)
	}
	destination, err := publication.NewResourceDestination(publication.ResourceDestinationParams{
		RuleID: rule.ID(), Scope: rule.Scope(), ResourceID: resourceID,
		ResourceVersion: 3, TargetGeneration: 2, InventoryRevision: 7,
		DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: resourceHash,
	})
	if err != nil {
		t.Fatalf("publication.NewResourceDestination() error = %v", err)
	}
	candidate, err := publication.NewCandidateWithResourceDestinations(
		trusted.Candidate().Snapshot(),
		[]publication.ResourceDestination{destination},
	)
	if err != nil {
		t.Fatalf("publication.NewCandidateWithResourceDestinations() error = %v", err)
	}
	command, err := publication.NewCommand(publication.CommandParams{
		Candidate: candidate, BasePolicyRevision: trusted.BasePolicyRevision(),
		ActorPrincipalID: trusted.ActorPrincipalID(), AuditReason: trusted.AuditReason(),
	})
	if err != nil {
		t.Fatalf("publication.NewCommand() error = %v", err)
	}
	return command
}

func policyPublicationChangeFixture(
	t *testing.T,
	command publication.Command,
	resolution publication.Resolution,
) publication.Change {
	t.Helper()
	change, err := publication.NewChange(publication.ChangeParams{
		Command:     command,
		Resolution:  resolution,
		MutationIDs: policyPublicationMutationIDsFixture(t),
		OccurredAt:  time.Date(2026, time.September, 15, 8, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("publication.NewChange() error = %v", err)
	}
	return change
}

func policyPublicationMutationIDsFixture(t *testing.T) publication.MutationIDs {
	t.Helper()
	ids, err := publication.NewMutationIDs(publication.MutationIDParams{
		ChangeID:      policyPublicationPublicIDFixture(t, "000000000910"),
		AuditEventID:  policyPublicationPublicIDFixture(t, "000000000911"),
		OutboxEventID: policyPublicationPublicIDFixture(t, "000000000912"),
		ReleaseID:     policyPublicationReleaseIDFixture(t, "000000000913"),
		ProjectionIDs: []publication.ProjectionID{
			policyPublicationProjectionIDFixture(t, "000000000914"),
		},
	})
	if err != nil {
		t.Fatalf("publication.NewMutationIDs() error = %v", err)
	}
	return ids
}

func policyPublicationPublicIDFixture(t *testing.T, suffix string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}

func policyPublicationReleaseIDFixture(t *testing.T, suffix string) publication.ReleaseID {
	t.Helper()
	id, err := publication.ParseReleaseID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publication.ParseReleaseID() error = %v", err)
	}
	return id
}

func policyPublicationProjectionIDFixture(t *testing.T, suffix string) publication.ProjectionID {
	t.Helper()
	id, err := publication.ParseProjectionID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publication.ParseProjectionID() error = %v", err)
	}
	return id
}

func policyPublicationCallQueries(calls []policyPublicationTestCall) []string {
	queries := make([]string, len(calls))
	for index, call := range calls {
		queries[index] = call.query
	}
	return queries
}

func findPolicyPublicationCall(
	t *testing.T,
	calls []policyPublicationTestCall,
	query string,
) policyPublicationTestCall {
	t.Helper()
	for _, call := range calls {
		if call.query == query {
			return call
		}
	}
	t.Fatalf("policy publication query not found: %s", query)
	return policyPublicationTestCall{}
}
