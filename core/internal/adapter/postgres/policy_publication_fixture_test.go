package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	publication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/workspace"
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
	if query == transactionTimeSQL {
		// Every unit of work reads its time on the database clock.
		return policyPublicationTestRow{scan: func(destinations ...any) error {
			*destinations[0].(*time.Time) = time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
			return nil
		}}
	}
	transaction.record(query, arguments)
	queued := transaction.rows[query]
	if len(queued) == 0 && query == scaledPolicyPublicationGrantedSQL {
		// Unless a test grants it, runtime may not run publish v2.
		return policyPublicationTestRow{scan: func(destinations ...any) error {
			*destinations[0].(*bool) = false
			return nil
		}}
	}
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
		ApprovalMode:      PolicyPublicationApprovalModeQualificationBypass,
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
	options.ApprovalMode = PolicyPublicationApprovalModePublisherAuthorized
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

func beginApprovalRequiredTestPolicyPublicationStore(
	t *testing.T,
	databaseTransaction *fakePolicyPublicationTransaction,
) *PolicyPublicationStore {
	t.Helper()
	options := testPolicyPublicationOptions()
	options.AllowTrustedActor = false
	options.ApprovalMode = PolicyPublicationApprovalModeRequired
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

func enqueueApprovedPolicyPublicationApply(
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
	transaction.enqueueRow(consumePolicyPublicationApprovalSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 3
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

func enqueuePolicyResourceGroupPublicationApply(
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
	transaction.enqueueRow(attachPolicyResourceGroupDestinationsSQL, policyPublicationTestRow{
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

func policyApprovedManagementPublicationCommandFixture(t *testing.T) publication.Command {
	t.Helper()
	trusted := policyPublicationCommandFixture(t)
	evidenceID, err := publication.ParseApprovalEvidenceID(
		"01890f00-0000-7000-8000-000000000551",
	)
	if err != nil {
		t.Fatalf("publication.ParseApprovalEvidenceID() error = %v", err)
	}
	command, err := publication.NewApprovedManagementCommand(publication.ManagementCommandParams{
		Candidate: trusted.Candidate(), BasePolicyRevision: trusted.BasePolicyRevision(),
		AccountSession: deviceRevocationAccountSessionFixture(
			t,
			trusted.ActorPrincipalID(),
			trusted.Candidate().Snapshot().Scope().WorkspaceID(),
		),
		ApprovalEvidenceID: evidenceID,
		AuditReason:        trusted.AuditReason(),
	})
	if err != nil {
		t.Fatalf("publication.NewApprovedManagementCommand() error = %v", err)
	}
	return command
}

func enqueuePolicyPublicationApproval(
	t *testing.T,
	transaction *fakePolicyPublicationTransaction,
	command publication.Command,
	networkRevision int64,
	policyRevision int64,
) {
	t.Helper()
	candidateHash := command.Candidate().SemanticHash().Bytes()
	impactHash := sha256.Sum256([]byte("complete Policy approval impact"))
	transaction.enqueueRow(lockPolicyPublicationApprovalSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = "01890f00-0000-7000-8000-000000000550"
			*destinations[1].(*string) = command.ApprovalEvidenceID().String()
			baseline := [...]int64{networkRevision, 1, 1, policyRevision, 1, 1, 1, 1}
			proposed := [...]int64{networkRevision + 1, 1, 1, policyRevision + 1, 1, 1, 1, 1}
			for index, value := range baseline {
				*destinations[index+2].(*int64) = value
			}
			for index, value := range proposed {
				*destinations[index+10].(*int64) = value
			}
			*destinations[18].(*[]byte) = append([]byte(nil), candidateHash[:]...)
			*destinations[19].(*int) = command.Candidate().CompilerFormatVersion()
			*destinations[20].(*[]byte) = append([]byte(nil), impactHash[:]...)
			*destinations[21].(*int64) = 2
			*destinations[22].(*int64) = 1
			*destinations[23].(*time.Time) = policyPublicationTestTime.Add(-time.Minute)
			*destinations[24].(*time.Time) = policyPublicationTestTime.Add(9 * time.Minute)
			*destinations[25].(*string) = "01890f00-0000-7000-8000-000000000631"
			*destinations[26].(*string) = "01890f00-0000-7000-8000-000000000632"
			*destinations[27].(*string) = "01890f00-0000-7000-8000-000000000633"
			*destinations[28].(*string) = "01890f00-0000-7000-8000-000000000634"
			for index, value := range [...]int64{2, 3, 4, 5, 6} {
				*destinations[index+29].(*int64) = value
			}
			return nil
		},
	})
	enqueuePolicyPublicationAuthorization(transaction)
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

func policyResourceGroupPublicationCommandFixture(t *testing.T) publication.Command {
	t.Helper()
	trusted := policyPublicationCommandFixture(t)
	rule := trusted.Candidate().Snapshot().Rules()[0]
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000921")
	if err != nil {
		t.Fatalf("resource.ParseID() error = %v", err)
	}
	groupID, err := resource.ParseGroupID("01890f00-0000-7000-8000-000000000922")
	if err != nil {
		t.Fatalf("resource.ParseGroupID() error = %v", err)
	}
	resourceHash, err := resource.NewSemanticHash(sha256.Sum256([]byte("synthetic group Resource")))
	if err != nil {
		t.Fatalf("resource.NewSemanticHash() error = %v", err)
	}
	member, err := publication.NewResourceGroupMemberDestination(
		publication.ResourceGroupMemberDestinationParams{
			Scope: rule.Scope(), ResourceID: resourceID, ResourceVersion: 3,
			TargetGeneration: 2, InventoryRevision: 7,
			DestinationNodeID: rule.DestinationNodeID(), ResourceSemanticHash: resourceHash,
		},
	)
	if err != nil {
		t.Fatalf("publication.NewResourceGroupMemberDestination() error = %v", err)
	}
	groupHash, err := resource.NewSemanticHash(sha256.Sum256([]byte("synthetic Resource Group")))
	if err != nil {
		t.Fatalf("resource.NewSemanticHash() error = %v", err)
	}
	destination, err := publication.NewResourceGroupDestination(
		publication.ResourceGroupDestinationParams{
			RuleID: rule.ID(), Scope: rule.Scope(), ResourceGroupID: groupID,
			GroupVersion: 2, DefinitionVersion: 2, GroupRevision: 8,
			GroupSemanticHash: groupHash,
			Members:           []publication.ResourceGroupMemberDestination{member},
		},
	)
	if err != nil {
		t.Fatalf("publication.NewResourceGroupDestination() error = %v", err)
	}
	candidate, err := publication.NewCandidateWithResourceGroupDestinations(
		trusted.Candidate().Snapshot(), nil, []publication.ResourceGroupDestination{destination},
	)
	if err != nil {
		t.Fatalf("publication.NewCandidateWithResourceGroupDestinations() error = %v", err)
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

func policyImportedResourcePublicationCommandFixture(t *testing.T) publication.Command {
	t.Helper()
	trusted := policyPublicationCommandFixture(t)
	consumerScope := trusted.Candidate().Snapshot().Scope()
	providerWorkspaceID, err := workspace.ParseID(
		"01890f00-0000-7000-8000-000000000102",
	)
	if err != nil {
		t.Fatal(err)
	}
	providerNetworkID, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	providerScope, err := network.NewScope(providerWorkspaceID, providerNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	resourceID, err := resource.ParseID("01890f00-0000-7000-8000-000000000923")
	if err != nil {
		t.Fatal(err)
	}
	resourceHash, err := resource.NewSemanticHash(
		sha256.Sum256([]byte("synthetic imported policy Resource")),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := sharing.NewResourceBinding(
		providerScope,
		resourceID,
		3,
		2,
		resourceHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	portRange, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{portRange},
	})
	if err != nil {
		t.Fatal(err)
	}
	traffic, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	if err != nil {
		t.Fatal(err)
	}
	importedID, err := sharing.ParseImportedResourceID(
		"01890f00-0000-7000-8000-000000000924",
	)
	if err != nil {
		t.Fatal(err)
	}
	contractID, err := sharing.ParseContractID("01890f00-0000-7000-8000-000000000925")
	if err != nil {
		t.Fatal(err)
	}
	offerID, err := sharing.ParseOfferID("01890f00-0000-7000-8000-000000000926")
	if err != nil {
		t.Fatal(err)
	}
	exportID, err := sharing.ParseExportID("01890f00-0000-7000-8000-000000000927")
	if err != nil {
		t.Fatal(err)
	}
	contract, err := sharing.NewContract(sharing.ContractParams{
		ID: contractID, ImportedResourceID: importedID, OfferID: offerID, ExportID: exportID,
		ProviderScope: providerScope, ConsumerScope: consumerScope, Resource: binding,
		MaximumTraffic: traffic, ProviderAuthorityGeneration: 2,
		ConsumerAuthorityGeneration: 3, RecoveryEpoch: 4,
		ExpiresAt: policyPublicationTestTime.Add(time.Hour), State: sharing.ContractStateActive,
		Version: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := sharing.NewPolicyDestination(sharing.PolicyDestinationParams{
		ImportedResourceID: importedID, ImportedResourceVersion: 2, Contract: contract,
		ExportVersion: 1, ProviderInventoryRevision: 7, ProviderSharingRevision: 8,
		ConsumerSharingRevision: 9, EvaluatedAt: policyPublicationTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000828")
	if err != nil {
		t.Fatal(err)
	}
	sourceID := trusted.Candidate().Snapshot().Rules()[0].SourceNodeID()
	destination, err := publication.NewImportedResourceDestination(
		publication.ImportedResourceDestinationParams{
			RuleID: ruleID, SourceNodeID: sourceID, Resolution: resolution,
			Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{portRange},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: consumerScope, Revision: 2, Rules: []policy.Rule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := publication.NewCandidateWithImportedResourceDestinations(
		snapshot,
		nil,
		nil,
		[]publication.ImportedResourceDestination{destination},
	)
	if err != nil {
		t.Fatal(err)
	}
	command, err := publication.NewCommand(publication.CommandParams{
		Candidate: candidate, BasePolicyRevision: trusted.BasePolicyRevision(),
		ActorPrincipalID: trusted.ActorPrincipalID(), AuditReason: trusted.AuditReason(),
	})
	if err != nil {
		t.Fatal(err)
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

func approvedPolicyPublicationChangeFixture(
	t *testing.T,
	command publication.Command,
	resolution publication.Resolution,
) publication.Change {
	t.Helper()
	change, err := publication.NewChange(publication.ChangeParams{
		Command: command, Resolution: resolution,
		MutationIDs: policyPublicationMutationIDsFixture(t),
		OccurredAt:  policyPublicationTestTime,
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
