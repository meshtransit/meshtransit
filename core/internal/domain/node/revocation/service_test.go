package revocation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/revocation"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/idempotency"
)

func TestServiceRevokesActiveDevice(t *testing.T) {
	t.Parallel()

	command := revocationCommandFixture(t)
	resolution := openRevocationResolutionFixture(t, command)
	transaction := &fakeRevocationTransaction{resolution: resolution}
	service := newRevocationServiceFixture(t, &fakeRevocationTransactions{
		transactions: []*fakeRevocationTransaction{transaction},
	}, &fakeCommittedRevocationResolver{}, fixedRevocationMutationIDs(t))

	result, err := service.Revoke(context.Background(), command)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if !result.IsValid() || result.Scope() != command.Scope() ||
		result.NodeID() != command.NodeID() ||
		result.DeviceVersion() != command.ExpectedVersion()+1 ||
		result.SessionGeneration() != resolution.SessionGeneration()+1 ||
		result.NetworkRevision() != resolution.NetworkRevision()+1 ||
		result.InventoryRevision() != resolution.InventoryRevision()+1 ||
		!transaction.committed || transaction.rolledBack || transaction.applyCalls != 1 {
		t.Fatalf("Revoke() result/transaction = %+v/%+v", result, transaction)
	}
	if transaction.attempt.MutationIDs() != fixedRevocationMutationIDs(t) ||
		!transaction.attempt.OccurredAt().Equal(revocationDecisionTime()) {
		t.Fatal("Revoke() did not preserve stable attempt identity and time")
	}
}

func TestServiceRejectsExpiredAccountSessionBeforeTransaction(t *testing.T) {
	t.Parallel()

	base := revocationCommandFixture(t)
	session := base.AccountSession()
	loginWorkspaceID, hasLoginWorkspace := session.LoginWorkspaceID()
	expiredSession, err := accountsession.NewSession(accountsession.Params{
		ID:                           session.ID(),
		DeploymentID:                 session.DeploymentID(),
		PrincipalID:                  session.PrincipalID(),
		IdentitySubjectID:            session.IdentitySubjectID(),
		LoginWorkspaceID:             loginWorkspaceID,
		HasLoginWorkspace:            hasLoginWorkspace,
		AuthenticationTime:           session.AuthenticationTime(),
		ACR:                          session.ACR(),
		AMR:                          session.AMR(),
		Version:                      session.Version(),
		PrincipalAuthorityGeneration: session.PrincipalAuthorityGeneration(),
		AccountSessionGeneration:     session.AccountSessionGeneration(),
		ProviderGeneration:           session.ProviderGeneration(),
		DeploymentRecoveryEpoch:      session.DeploymentRecoveryEpoch(),
		IdleExpiresAt:                revocationDecisionTime().Add(-time.Second),
		AbsoluteExpiresAt:            session.AbsoluteExpiresAt(),
	})
	if err != nil {
		t.Fatalf("construct expired Account Session: %v", err)
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope:               base.Scope(),
		NodeID:              base.NodeID(),
		ExpectedVersion:     base.ExpectedVersion(),
		AccountSession:      expiredSession,
		Reason:              base.Reason(),
		IdempotencyEvidence: base.IdempotencyEvidence(),
	})
	if err != nil {
		t.Fatalf("construct expired-session command: %v", err)
	}
	transactions := &fakeRevocationTransactions{}
	service := newRevocationServiceFixture(
		t,
		transactions,
		&fakeCommittedRevocationResolver{},
		fixedRevocationMutationIDs(t),
	)

	if _, err := service.Revoke(context.Background(), command); !errors.Is(
		err,
		revocation.ErrForbidden,
	) {
		t.Fatalf("Revoke() error = %v, want ErrForbidden", err)
	}
	if transactions.beginCalls != 0 {
		t.Fatalf("transaction begins = %d, want 0", transactions.beginCalls)
	}
}

func TestServiceRetriesWholeTransactionWithStableAttempt(t *testing.T) {
	t.Parallel()

	command := revocationCommandFixture(t)
	first := &fakeRevocationTransaction{resolveErr: revocation.ErrRetryableTransaction}
	second := &fakeRevocationTransaction{resolution: openRevocationResolutionFixture(t, command)}
	waits := &recordingRetryWaiter{}
	transactions := &fakeRevocationTransactions{
		transactions: []*fakeRevocationTransaction{first, second},
	}
	service := newRevocationServiceFixtureWithRetry(
		t,
		transactions,
		&fakeCommittedRevocationResolver{},
		fixedRevocationMutationIDs(t),
		waits,
	)

	if _, err := service.Revoke(context.Background(), command); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if !first.rolledBack || first.committed || !second.committed || second.rolledBack ||
		len(waits.attempts) != 1 || waits.attempts[0] != 1 {
		t.Fatalf("retry lifecycle first=%+v second=%+v waits=%v", first, second, waits.attempts)
	}
	if first.attempt.MutationIDs() != second.attempt.MutationIDs() ||
		!first.attempt.OccurredAt().Equal(second.attempt.OccurredAt()) ||
		!first.attempt.ExpiresAt().Equal(second.attempt.ExpiresAt()) {
		t.Fatal("whole-transaction retry changed stable attempt evidence")
	}
}

func TestServiceReturnsCompletedIdempotentReplay(t *testing.T) {
	t.Parallel()

	command := revocationCommandFixture(t)
	open := openRevocationResolutionFixture(t, command)
	result := revocationResultFixture(t, open)
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	completed, err := revocation.NewCompletedResolution(result, hash)
	if err != nil {
		t.Fatalf("NewCompletedResolution() error = %v", err)
	}
	transaction := &fakeRevocationTransaction{resolution: completed}
	service := newRevocationServiceFixture(t, &fakeRevocationTransactions{
		transactions: []*fakeRevocationTransaction{transaction},
	}, &fakeCommittedRevocationResolver{}, fixedRevocationMutationIDs(t))

	replayed, err := service.Revoke(context.Background(), command)
	if err != nil {
		t.Fatalf("Revoke() replay error = %v", err)
	}
	if replayed != result || transaction.applyCalls != 0 || transaction.committed ||
		!transaction.rolledBack {
		t.Fatalf("replay result/transaction = %+v/%+v", replayed, transaction)
	}
}

func TestServiceResolvesUnknownCommitFromIdempotencyEvidence(t *testing.T) {
	t.Parallel()

	command := revocationCommandFixture(t)
	resolution := openRevocationResolutionFixture(t, command)
	result := revocationResultFixture(t, resolution)
	transaction := &fakeRevocationTransaction{
		resolution: resolution,
		commitErr:  revocation.ErrCommitOutcomeUnknown,
	}
	resolver := &fakeCommittedRevocationResolver{result: result, found: true}
	service := newRevocationServiceFixture(t, &fakeRevocationTransactions{
		transactions: []*fakeRevocationTransaction{transaction},
	}, resolver, fixedRevocationMutationIDs(t))

	resolved, err := service.Revoke(context.Background(), command)
	if err != nil {
		t.Fatalf("Revoke() unknown commit error = %v", err)
	}
	if resolved != result || resolver.calls != 1 || !transaction.rolledBack {
		t.Fatalf("unknown commit result/resolver/transaction = %+v/%d/%+v", resolved, resolver.calls, transaction)
	}
}

func TestServiceRejectsUnsafeLifecycleAndCAS(t *testing.T) {
	t.Parallel()

	command := revocationCommandFixture(t)
	tests := []struct {
		name    string
		mutate  func(*revocation.OpenResolutionParams)
		wantErr error
	}{
		{
			name: "stale expected version",
			mutate: func(params *revocation.OpenResolutionParams) {
				params.DeviceVersion++
			},
			wantErr: revocation.ErrConflict,
		},
		{
			name: "already revoked",
			mutate: func(params *revocation.OpenResolutionParams) {
				params.DeviceState = revocation.DeviceStateRevoked
				params.MachineKeyState = revocation.KeyStateRevoked
				params.NodeKeyState = revocation.KeyStateRevoked
			},
			wantErr: revocation.ErrAlreadyRevoked,
		},
		{
			name: "expired Node key",
			mutate: func(params *revocation.OpenResolutionParams) {
				params.NodeKeyState = revocation.KeyStateExpired
			},
			wantErr: revocation.ErrInvalidTransition,
		},
		{
			name: "future machine key",
			mutate: func(params *revocation.OpenResolutionParams) {
				params.MachineKeyValidFrom = revocationDecisionTime().Add(time.Second)
			},
			wantErr: revocation.ErrInvalidTransition,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			params := openRevocationResolutionParamsFixture(t, command)
			test.mutate(&params)
			resolution, err := revocation.NewOpenResolution(params)
			if err != nil {
				t.Fatalf("NewOpenResolution() error = %v", err)
			}
			transaction := &fakeRevocationTransaction{resolution: resolution}
			service := newRevocationServiceFixture(t, &fakeRevocationTransactions{
				transactions: []*fakeRevocationTransaction{transaction},
			}, &fakeCommittedRevocationResolver{}, fixedRevocationMutationIDs(t))

			if _, err := service.Revoke(context.Background(), command); !errors.Is(err, test.wantErr) {
				t.Fatalf("Revoke() error = %v, want %v", err, test.wantErr)
			}
			if transaction.applyCalls != 0 || transaction.committed || !transaction.rolledBack {
				t.Fatalf("rejected transaction = %+v", transaction)
			}
		})
	}
}

func TestCommandHashBindsRevocationSemantics(t *testing.T) {
	t.Parallel()

	command := revocationCommandFixture(t)
	base, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	reason, err := revocation.NewReason("different reason")
	if err != nil {
		t.Fatalf("NewReason() error = %v", err)
	}
	changed, err := revocation.NewCommand(revocation.CommandParams{
		Scope:               command.Scope(),
		NodeID:              command.NodeID(),
		ExpectedVersion:     command.ExpectedVersion(),
		AccountSession:      command.AccountSession(),
		Reason:              reason,
		IdempotencyEvidence: command.IdempotencyEvidence(),
	})
	if err != nil {
		t.Fatalf("NewCommand() error = %v", err)
	}
	other, err := changed.RequestHash()
	if err != nil {
		t.Fatalf("changed Command.RequestHash() error = %v", err)
	}
	if base == other {
		t.Fatal("request hash did not bind audit reason")
	}
}

func TestChangeHashesTerminalGenerationAndKeys(t *testing.T) {
	t.Parallel()

	command := revocationCommandFixture(t)
	resolution := openRevocationResolutionFixture(t, command)
	attempt, err := revocation.NewAttempt(
		fixedRevocationMutationIDs(t),
		revocationDecisionTime(),
		revocationDecisionTime().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewAttempt() error = %v", err)
	}
	change, err := revocation.NewChange(command, resolution, attempt)
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	if change.BeforeSemanticHash() == change.AfterSemanticHash() {
		t.Fatal("terminal authority hash equals active authority hash")
	}
}

type fakeRevocationTransactions struct {
	transactions []*fakeRevocationTransaction
	beginCalls   int
}

func (transactions *fakeRevocationTransactions) Begin(
	_ context.Context,
	_ network.Scope,
) (revocation.Transaction, error) {
	if transactions.beginCalls >= len(transactions.transactions) {
		return nil, errors.New("unexpected transaction begin")
	}
	transaction := transactions.transactions[transactions.beginCalls]
	transactions.beginCalls++
	return transaction, nil
}

type fakeRevocationTransaction struct {
	resolution revocation.Resolution
	resolveErr error
	commitErr  error
	attempt    revocation.Attempt
	applyCalls int
	committed  bool
	rolledBack bool
}

func (transaction *fakeRevocationTransaction) Resolve(
	_ context.Context,
	_ revocation.Command,
	attempt revocation.Attempt,
) (revocation.Resolution, error) {
	transaction.attempt = attempt
	return transaction.resolution, transaction.resolveErr
}

func (transaction *fakeRevocationTransaction) Apply(
	_ context.Context,
	change revocation.Change,
) (revocation.Result, error) {
	transaction.applyCalls++
	return revocationResultFixture(nil, change.Resolution()), nil
}

func (transaction *fakeRevocationTransaction) Commit(context.Context) error {
	transaction.committed = true
	return transaction.commitErr
}

func (transaction *fakeRevocationTransaction) Rollback(context.Context) error {
	transaction.rolledBack = true
	return nil
}

type fakeCommittedRevocationResolver struct {
	result revocation.Result
	found  bool
	err    error
	calls  int
}

func (resolver *fakeCommittedRevocationResolver) ResolveCommitted(
	context.Context,
	revocation.Command,
	revocation.Attempt,
) (revocation.Result, bool, error) {
	resolver.calls++
	return resolver.result, resolver.found, resolver.err
}

type fixedMutationIDGenerator struct{ ids revocation.MutationIDs }

func (generator fixedMutationIDGenerator) NewMutationIDs() (revocation.MutationIDs, error) {
	return generator.ids, nil
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type recordingRetryWaiter struct{ attempts []int }

func (waiter *recordingRetryWaiter) Wait(_ context.Context, attempt int) error {
	waiter.attempts = append(waiter.attempts, attempt)
	return nil
}

func newRevocationServiceFixture(
	t *testing.T,
	transactions revocation.Transactions,
	resolver revocation.CommittedResultResolver,
	ids revocation.MutationIDs,
) *revocation.Service {
	t.Helper()
	return newRevocationServiceFixtureWithRetry(
		t,
		transactions,
		resolver,
		ids,
		&recordingRetryWaiter{},
	)
}

func newRevocationServiceFixtureWithRetry(
	t *testing.T,
	transactions revocation.Transactions,
	resolver revocation.CommittedResultResolver,
	ids revocation.MutationIDs,
	retry revocation.RetryWaiter,
) *revocation.Service {
	t.Helper()
	service, err := revocation.NewService(
		revocation.Options{
			MaxAttempts:     3,
			RollbackTimeout: time.Second,
			IdempotencyTTL:  time.Hour,
		},
		revocation.Dependencies{
			Transactions:     transactions,
			CommittedResults: resolver,
			MutationIDs:      fixedMutationIDGenerator{ids: ids},
			Clock:            fixedClock{now: revocationDecisionTime()},
			Retry:            retry,
		},
	)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func revocationCommandFixture(t *testing.T) revocation.Command {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("parse Workspace ID: %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("parse Network ID: %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("construct Network scope: %v", err)
	}
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatalf("parse Node ID: %v", err)
	}
	actorID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	if err != nil {
		t.Fatalf("parse actor ID: %v", err)
	}
	reason, err := revocation.NewReason("compromised test device")
	if err != nil {
		t.Fatalf("construct reason: %v", err)
	}
	proof, err := idempotency.NewProof("test-key-v1", [32]byte{31: 9})
	if err != nil {
		t.Fatalf("construct idempotency proof: %v", err)
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope:               scope,
		NodeID:              nodeID,
		ExpectedVersion:     1,
		AccountSession:      revocationAccountSessionFixture(t, actorID, workspaceID),
		Reason:              reason,
		IdempotencyEvidence: proof,
	})
	if err != nil {
		t.Fatalf("NewCommand() error = %v", err)
	}
	return command
}

func openRevocationResolutionFixture(
	t *testing.T,
	command revocation.Command,
) revocation.Resolution {
	t.Helper()
	resolution, err := revocation.NewOpenResolution(openRevocationResolutionParamsFixture(t, command))
	if err != nil {
		t.Fatalf("NewOpenResolution() error = %v", err)
	}
	return resolution
}

func openRevocationResolutionParamsFixture(
	t *testing.T,
	command revocation.Command,
) revocation.OpenResolutionParams {
	t.Helper()
	hash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	return revocation.OpenResolutionParams{
		IdempotencyRecordID: fixedRevocationMutationIDs(t).IdempotencyRecordID(),
		RequestHash:         hash,
		Authorization:       revocationAuthorizationEvidenceFixture(t, command),
		Scope:               command.Scope(),
		NodeID:              command.NodeID(),
		NetworkRevision:     7,
		InventoryRevision:   5,
		DeviceVersion:       1,
		SessionGeneration:   3,
		DeviceState:         revocation.DeviceStateActive,
		MachineKeyEpoch:     1,
		MachineKeyVersion:   1,
		MachineKeyState:     revocation.KeyStateActive,
		MachineKeyValidFrom: revocationDecisionTime().Add(-time.Hour),
		NodeKeyEpoch:        1,
		NodeKeyVersion:      1,
		NodeKeyState:        revocation.KeyStateActive,
		NodeKeyValidFrom:    revocationDecisionTime().Add(-time.Hour),
	}
}

func revocationAccountSessionFixture(
	t *testing.T,
	principalID identity.PrincipalID,
	workspaceID workspace.ID,
) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse Deployment ID: %v", err)
	}
	sessionID, err := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	if err != nil {
		t.Fatalf("parse Account Session ID: %v", err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(
		"01890f00-0000-7000-8000-000000000611",
	)
	if err != nil {
		t.Fatalf("parse identity subject ID: %v", err)
	}
	session, err := accountsession.NewSession(accountsession.Params{
		ID:                           sessionID,
		DeploymentID:                 deploymentID,
		PrincipalID:                  principalID,
		IdentitySubjectID:            subjectID,
		LoginWorkspaceID:             workspaceID,
		HasLoginWorkspace:            true,
		AuthenticationTime:           revocationDecisionTime().Add(-time.Hour),
		ACR:                          "urn:meshtransit:test",
		AMR:                          []string{"pwd"},
		Version:                      1,
		PrincipalAuthorityGeneration: 1,
		AccountSessionGeneration:     1,
		ProviderGeneration:           1,
		DeploymentRecoveryEpoch:      1,
		IdleExpiresAt:                revocationDecisionTime().Add(time.Hour),
		AbsoluteExpiresAt:            revocationDecisionTime().Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("construct Account Session: %v", err)
	}
	return session
}

func revocationAuthorizationEvidenceFixture(
	t *testing.T,
	command revocation.Command,
) revocation.AuthorizationEvidence {
	t.Helper()
	bindingID, err := publicid.Parse("01890f00-0000-7000-8000-000000000821")
	if err != nil {
		t.Fatalf("parse RoleBinding ID: %v", err)
	}
	roleID, err := publicid.Parse("01890f00-0000-7000-8000-000000000822")
	if err != nil {
		t.Fatalf("parse RoleDefinition ID: %v", err)
	}
	evidence, err := revocation.NewAuthorizationEvidence(revocation.AuthorizationEvidenceParams{
		AccountSessionID:              command.AccountSession().ID(),
		RoleBindingID:                 bindingID,
		RoleDefinitionID:              roleID,
		ScopeAuthorityGeneration:      authorization.AuthorityGeneration(1),
		MembershipAuthorityGeneration: authorization.AuthorityGeneration(1),
		BindingAuthorityGeneration:    authorization.AuthorityGeneration(1),
		RoleAuthorityGeneration:       authorization.AuthorityGeneration(1),
	})
	if err != nil {
		t.Fatalf("construct authorization evidence: %v", err)
	}
	return evidence
}

func revocationResultFixture(t *testing.T, resolution revocation.Resolution) revocation.Result {
	if t != nil {
		t.Helper()
	}
	result, err := revocation.NewResult(revocation.ResultParams{
		IdempotencyRecordID: resolution.IdempotencyRecordID(),
		Scope:               resolution.Scope(),
		NodeID:              resolution.NodeID(),
		DeviceVersion:       resolution.DeviceVersion() + 1,
		SessionGeneration:   resolution.SessionGeneration() + 1,
		NetworkRevision:     resolution.NetworkRevision() + 1,
		InventoryRevision:   resolution.InventoryRevision() + 1,
	})
	if err != nil {
		panic(err)
	}
	return result
}

func fixedRevocationMutationIDs(t *testing.T) revocation.MutationIDs {
	if t != nil {
		t.Helper()
	}
	values := [4]string{
		"01890f00-0000-7000-8000-000000000501",
		"01890f00-0000-7000-8000-000000000502",
		"01890f00-0000-7000-8000-000000000503",
		"01890f00-0000-7000-8000-000000000504",
	}
	var ids [4]publicid.ID
	for index, value := range values {
		parsed, err := publicid.Parse(value)
		if err != nil {
			panic(err)
		}
		ids[index] = parsed
	}
	result, err := revocation.NewMutationIDs(revocation.MutationIDParams{
		IdempotencyRecordID: ids[0],
		ChangeID:            ids[1],
		AuditEventID:        ids[2],
		OutboxEventID:       ids[3],
	})
	if err != nil {
		panic(err)
	}
	return result
}

func revocationDecisionTime() time.Time {
	return time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
}
