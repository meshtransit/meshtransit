package authority

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/idempotency"
)

func TestServiceCommitsDeviceResource(t *testing.T) {
	command := authorityCommandFixture(t, OperationCreateDevice)
	ids := authorityMutationIDsFixture(t, command)
	resolution := authorityResolutionFixture(t, command, ids, 7, 3, 2)
	transaction := &fakeAuthorityTransaction{resolution: resolution}
	transactions := &fakeAuthorityTransactions{transactions: []*fakeAuthorityTransaction{transaction}}
	service := authorityServiceFixture(t, transactions, ids)

	result, err := service.Create(t.Context(), command)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.ResourceID() != ids.ResourceID() || result.NetworkRevision() != 8 ||
		result.SubsystemRevision() != 4 || transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("Create() result = %+v transaction = %+v", result, transaction)
	}
}

func TestServiceRejectsStaleRevisionAndRollsBack(t *testing.T) {
	command := authorityCommandFixture(t, OperationCreateDevice)
	ids := authorityMutationIDsFixture(t, command)
	resolution := authorityResolutionFixture(t, command, ids, 7, 4, 2)
	transaction := &fakeAuthorityTransaction{resolution: resolution}
	service := authorityServiceFixture(
		t,
		&fakeAuthorityTransactions{transactions: []*fakeAuthorityTransaction{transaction}},
		ids,
	)

	if _, err := service.Create(t.Context(), command); !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() error = %v, want ErrConflict", err)
	}
	if transaction.commits != 0 || transaction.rollbacks != 1 || transaction.applies != 0 {
		t.Fatalf("stale transaction = %+v", transaction)
	}
}

func TestServiceRetriesWholeTransactionWithStableDecision(t *testing.T) {
	command := authorityCommandFixture(t, OperationCreateGroup)
	ids := authorityMutationIDsFixture(t, command)
	resolution := authorityResolutionFixture(t, command, ids, 7, 3, 2)
	first := &fakeAuthorityTransaction{
		resolution: resolution,
		applyErr:   errors.Join(ErrRetryableTransaction, errors.New("serialization")),
	}
	second := &fakeAuthorityTransaction{resolution: resolution}
	transactions := &fakeAuthorityTransactions{
		transactions: []*fakeAuthorityTransaction{first, second},
	}
	service := authorityServiceFixture(t, transactions, ids)

	result, err := service.Create(t.Context(), command)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.GroupID() != ids.GroupID() || first.rollbacks != 1 || second.commits != 1 ||
		len(first.changes) != 1 || len(second.changes) != 1 ||
		first.changes[0].MutationIDs().ChangeID() != second.changes[0].MutationIDs().ChangeID() ||
		!first.changes[0].OccurredAt().Equal(second.changes[0].OccurredAt()) {
		t.Fatalf("retry result=%+v first=%+v second=%+v", result, first, second)
	}
}

func TestServiceResolvesUnknownCommitByStableAggregateID(t *testing.T) {
	command := authorityCommandFixture(t, OperationCreateDevice)
	ids := authorityMutationIDsFixture(t, command)
	resolution := authorityResolutionFixture(t, command, ids, 7, 3, 2)
	committed, err := NewResult(
		command.Operation(), ids.ResourceID(), ids.GroupID(), command.Scope(),
		8, 4, 1, command.SemanticHash(),
	)
	if err != nil {
		t.Fatalf("NewResult() error = %v", err)
	}
	transaction := &fakeAuthorityTransaction{
		resolution: resolution,
		commitErr:  errors.Join(ErrCommitOutcomeUnknown, errors.New("lost ACK")),
	}
	transactions := &fakeAuthorityTransactions{
		transactions: []*fakeAuthorityTransaction{transaction},
		committed:    committed,
		found:        true,
	}
	service := authorityServiceFixture(t, transactions, ids)

	result, err := service.Create(t.Context(), command)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.ResourceID() != ids.ResourceID() || transactions.resolves != 1 ||
		transaction.commits != 1 || transaction.rollbacks != 1 {
		t.Fatalf("resolved result=%+v transactions=%+v transaction=%+v", result, transactions, transaction)
	}
}

func TestServiceReturnsCompletedIdempotentReplayWithoutMutation(t *testing.T) {
	command := authorityCommandFixture(t, OperationCreateDevice)
	ids := authorityMutationIDsFixture(t, command)
	committed, err := NewResult(
		command.Operation(), ids.ResourceID(), ids.GroupID(), command.Scope(),
		8, 4, 1, command.SemanticHash(),
	)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := NewCompletedResolution(
		committed, ids.IdempotencyRecordID(), requestHash,
	)
	if err != nil {
		t.Fatal(err)
	}
	transaction := &fakeAuthorityTransaction{resolution: resolution}
	service := authorityServiceFixture(
		t,
		&fakeAuthorityTransactions{transactions: []*fakeAuthorityTransaction{transaction}},
		ids,
	)

	result, err := service.Create(t.Context(), command)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result != committed || transaction.applies != 0 || transaction.commits != 0 ||
		transaction.rollbacks != 1 {
		t.Fatalf("replay result=%+v transaction=%+v", result, transaction)
	}
}

func TestCreateCommandRequiresCreatorOwnership(t *testing.T) {
	definition := authorityDeviceDefinitionFixture(t)
	otherSession := authoritySessionFixture(t, authorityPrincipalID(t, 12))
	reason, err := NewAuditReason("invalid delegated ownership")
	if err != nil {
		t.Fatalf("NewAuditReason() error = %v", err)
	}
	if _, err := NewCreateDeviceCommand(
		definition, 3, otherSession, reason, authorityIdempotencyProofFixture(t),
	); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("NewCreateDeviceCommand() error = %v, want ErrInvalidCommand", err)
	}
}

type fakeAuthorityTransactions struct {
	transactions []*fakeAuthorityTransaction
	begins       int
	committed    Result
	found        bool
	resolveErr   error
	resolves     int
}

func (transactions *fakeAuthorityTransactions) Begin(
	_ context.Context,
	_ network.Scope,
) (Transaction, error) {
	if transactions.begins >= len(transactions.transactions) {
		return nil, errors.New("unexpected begin")
	}
	transaction := transactions.transactions[transactions.begins]
	transactions.begins++
	return transaction, nil
}

func (transactions *fakeAuthorityTransactions) ResolveCommitted(
	context.Context,
	Command,
	MutationIDs,
) (Result, bool, error) {
	transactions.resolves++
	return transactions.committed, transactions.found, transactions.resolveErr
}

type fakeAuthorityTransaction struct {
	resolution Resolution
	applyErr   error
	commitErr  error
	changes    []Change
	applies    int
	commits    int
	rollbacks  int
}

func (transaction *fakeAuthorityTransaction) Resolve(
	context.Context,
	Command,
	MutationIDs,
	time.Time,
	time.Time,
) (Resolution, error) {
	return transaction.resolution, nil
}

func (transaction *fakeAuthorityTransaction) Apply(
	_ context.Context,
	change Change,
) (Result, error) {
	transaction.applies++
	transaction.changes = append(transaction.changes, change)
	if transaction.applyErr != nil {
		return Result{}, transaction.applyErr
	}
	command := change.Command()
	subsystemRevision := change.Resolution().InventoryRevision() + 1
	if command.Operation() == OperationCreateGroup {
		subsystemRevision = change.Resolution().GroupRevision() + 1
	}
	return NewResult(
		command.Operation(),
		change.MutationIDs().ResourceID(),
		change.MutationIDs().GroupID(),
		command.Scope(),
		change.Resolution().NetworkRevision()+1,
		subsystemRevision,
		1,
		command.SemanticHash(),
	)
}

func (transaction *fakeAuthorityTransaction) Commit(context.Context) error {
	transaction.commits++
	return transaction.commitErr
}

func (transaction *fakeAuthorityTransaction) Rollback(context.Context) error {
	transaction.rollbacks++
	return nil
}

type fixedAuthorityMutationIDs struct{ ids MutationIDs }

func (generator fixedAuthorityMutationIDs) NewMutationIDs(Command) (MutationIDs, error) {
	return generator.ids, nil
}

type fixedAuthorityClock struct{ now time.Time }

func (clock fixedAuthorityClock) Now() time.Time { return clock.now }

type noAuthorityRetryDelay struct{}

func (noAuthorityRetryDelay) Wait(context.Context, int) error { return nil }

func authorityServiceFixture(
	t *testing.T,
	transactions *fakeAuthorityTransactions,
	ids MutationIDs,
) *Service {
	t.Helper()
	service, err := NewService(
		Options{
			MaxAttempts: 3, RollbackTimeout: time.Second,
			IdempotencyWindow: time.Hour,
		},
		Dependencies{
			Transactions: transactions, CommittedResults: transactions,
			MutationIDs: fixedAuthorityMutationIDs{ids: ids},
			Clock:       fixedAuthorityClock{now: time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)},
			Retry:       noAuthorityRetryDelay{},
		},
	)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func authorityCommandFixture(t *testing.T, operation Operation) Command {
	t.Helper()
	principalID := authorityPrincipalID(t, 11)
	session := authoritySessionFixture(t, principalID)
	reason, err := NewAuditReason("qualification creation")
	if err != nil {
		t.Fatalf("NewAuditReason() error = %v", err)
	}
	if operation == OperationCreateDevice {
		command, err := NewCreateDeviceCommand(
			authorityDeviceDefinitionFixture(t), 3, session, reason,
			authorityIdempotencyProofFixture(t),
		)
		if err != nil {
			t.Fatalf("NewCreateDeviceCommand() error = %v", err)
		}
		return command
	}
	scope := authorityScopeFixture(t)
	resourceID, err := resource.ParseID(authorityPublicID(401))
	if err != nil {
		t.Fatalf("resource.ParseID() error = %v", err)
	}
	reference, err := resource.NewReference(scope, resourceID, 1, 1)
	if err != nil {
		t.Fatalf("resource.NewReference() error = %v", err)
	}
	name, err := resource.ParseDisplayName("Database servers")
	if err != nil {
		t.Fatalf("resource.ParseDisplayName() error = %v", err)
	}
	definition, err := resource.NewGroupDefinition(resource.GroupDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: principalID,
		CustodianPrincipalID: principalID, Members: []resource.Reference{reference},
	})
	if err != nil {
		t.Fatalf("resource.NewGroupDefinition() error = %v", err)
	}
	command, err := NewCreateGroupCommand(
		definition, 2, session, reason, authorityIdempotencyProofFixture(t),
	)
	if err != nil {
		t.Fatalf("NewCreateGroupCommand() error = %v", err)
	}
	return command
}

func authorityDeviceDefinitionFixture(t *testing.T) resource.DeviceDefinition {
	t.Helper()
	principalID := authorityPrincipalID(t, 11)
	deviceID, err := node.ParseID(authorityPublicID(301))
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	name, err := resource.ParseDisplayName("Database 01")
	if err != nil {
		t.Fatalf("resource.ParseDisplayName() error = %v", err)
	}
	definition, err := resource.NewDeviceDefinition(resource.DeviceDefinitionParams{
		Scope: authorityScopeFixture(t), DisplayName: name,
		OwnerPrincipalID: principalID, CustodianPrincipalID: principalID,
		DeviceID: deviceID,
	})
	if err != nil {
		t.Fatalf("resource.NewDeviceDefinition() error = %v", err)
	}
	return definition
}

func authorityMutationIDsFixture(t *testing.T, command Command) MutationIDs {
	t.Helper()
	changeID := authorityPublicIDValue(t, 901)
	auditID := authorityPublicIDValue(t, 902)
	outboxID := authorityPublicIDValue(t, 903)
	idempotencyID := authorityPublicIDValue(t, 904)
	aggregateID := authorityPublicIDValue(t, 905)
	projectionCount := 1
	if command.Operation() == OperationCreateGroup {
		projectionCount += len(command.Group().Members())
	}
	projections := make([]publicid.ID, projectionCount)
	for index := range projections {
		projections[index] = authorityPublicIDValue(t, 906+index)
	}
	var resourceID resource.ID
	var groupID resource.GroupID
	if command.Operation() == OperationCreateDevice {
		resourceID = resource.ID(aggregateID)
	} else {
		groupID = resource.GroupID(aggregateID)
	}
	ids, err := NewMutationIDs(
		changeID, auditID, outboxID, idempotencyID, resourceID, groupID, projections,
	)
	if err != nil {
		t.Fatalf("NewMutationIDs() error = %v", err)
	}
	return ids
}

func authorityResolutionFixture(
	t *testing.T,
	command Command,
	ids MutationIDs,
	networkRevision, inventoryRevision, groupRevision int64,
) Resolution {
	t.Helper()
	requestHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	resolution, err := NewResolution(
		command.Scope(), networkRevision, inventoryRevision, groupRevision,
		ids.IdempotencyRecordID(), requestHash,
	)
	if err != nil {
		t.Fatalf("NewResolution() error = %v", err)
	}
	return resolution
}

func authorityIdempotencyProofFixture(t *testing.T) idempotency.Proof {
	t.Helper()
	digest := [32]byte{31: 1}
	proof, err := idempotency.NewProof("phase2-test-v1", digest)
	if err != nil {
		t.Fatalf("idempotency.NewProof() error = %v", err)
	}
	return proof
}

func authoritySessionFixture(
	t *testing.T,
	principalID identity.PrincipalID,
) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID(authorityPublicID(1))
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	sessionID, err := accountsession.ParseID(authorityPublicID(811))
	if err != nil {
		t.Fatalf("accountsession.ParseID() error = %v", err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(authorityPublicID(711))
	if err != nil {
		t.Fatalf("accountsession.ParseIdentitySubjectID() error = %v", err)
	}
	workspaceID, err := workspace.ParseID(authorityPublicID(101))
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("accountsession.NewSession() error = %v", err)
	}
	return session
}

func authorityScopeFixture(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID(authorityPublicID(101))
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID(authorityPublicID(201))
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func authorityPrincipalID(t *testing.T, suffix int) identity.PrincipalID {
	t.Helper()
	id, err := identity.ParsePrincipalID(authorityPublicID(suffix))
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	return id
}

func authorityPublicIDValue(t *testing.T, suffix int) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(authorityPublicID(suffix))
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}

func authorityPublicID(suffix int) string {
	value := "000" + strconv.Itoa(suffix)
	return "01890f00-0000-7000-8000-000000000" + value[len(value)-3:]
}
