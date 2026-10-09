package approval_test

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy/approval"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestServiceRequestsApprovalFromFreshCompilerIdenticalSimulation(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, request := approvalSimulationFixture(t, proposer)
	simulator := &approvalSimulatorFixture{result: simulated}
	transaction := &requestTransactionFixture{}
	transactions := &requestTransactionsFixture{
		transactions: []*requestTransactionFixture{transaction},
	}
	ids := &approvalIDGeneratorFixture{requestIDs: approvalRequestMutationIDsFixture(t)}
	clock := &approvalClockFixture{now: approvalTestTime()}
	retry := &approvalRetryFixture{}
	service := approvalServiceFixture(
		t,
		simulator,
		transactions,
		&approvalTransactionsFixture{},
		ids,
		clock,
		retry,
		nil,
		nil,
	)

	result, err := service.Request(
		t.Context(),
		approvalRequestIntentFixture(t, proposer, simulated, request),
	)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	expectedBinding, err := approval.NewBindingFromSimulation(simulated)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestID() != ids.requestIDs.RequestID() ||
		!result.Binding().Equal(expectedBinding) || result.State() != approval.StatePending ||
		result.ProposerPrincipalID() != proposer.PrincipalID() ||
		result.ProposerSessionID() != proposer.ID() || result.RequestVersion() != 1 ||
		!result.ExpiresAt().Equal(approvalTestTime().Add(approval.RequestLifetime)) ||
		simulator.calls != 1 || transactions.calls != 1 || ids.requestCalls != 1 ||
		clock.calls != 1 || retry.calls != 0 || transaction.resolveCalls != 1 ||
		transaction.applyCalls != 1 || transaction.commitCalls != 1 ||
		transaction.rollbackCalls != 0 {
		t.Fatalf(
			"result=%+v simulator=%+v transactions=%+v ids=%+v clock=%+v retry=%+v tx=%+v",
			result,
			simulator,
			transactions,
			ids,
			clock,
			retry,
			transaction,
		)
	}
}

func TestRequestUsesPostgreSQLTimestampPrecision(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, request := approvalSimulationFixture(t, proposer)
	instant := approvalTestTime().Add(789 * time.Nanosecond)
	service := approvalServiceFixture(
		t,
		&approvalSimulatorFixture{result: simulated},
		&requestTransactionsFixture{transactions: []*requestTransactionFixture{{}}},
		&approvalTransactionsFixture{},
		&approvalIDGeneratorFixture{requestIDs: approvalRequestMutationIDsFixture(t)},
		&approvalClockFixture{now: instant},
		&approvalRetryFixture{},
		nil,
		nil,
	)
	result, err := service.Request(
		t.Context(), approvalRequestIntentFixture(t, proposer, simulated, request),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CreatedAt().Equal(approvalTestTime()) ||
		!result.ExpiresAt().Equal(approvalTestTime().Add(approval.RequestLifetime)) ||
		result.ExpiresAt().After(instant.Add(approval.RequestLifetime)) {
		t.Fatalf("request timestamps = %s / %s", result.CreatedAt(), result.ExpiresAt())
	}
}

func TestServiceRejectsChangedProposalEvidenceBeforePersistence(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, request := approvalSimulationFixture(t, proposer)

	for _, test := range []struct {
		name      string
		candidate publication.SemanticHash
		impact    simulation.ImpactHash
		wantErr   error
	}{
		{
			name: "candidate changed", candidate: alternateSemanticHash(t),
			impact: simulated.ImpactHash(), wantErr: approval.ErrCandidateChanged,
		},
		{
			name: "impact changed", candidate: simulated.ProposedCandidate().SemanticHash(),
			impact: alternateImpactHash(t), wantErr: approval.ErrImpactChanged,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			intent, err := approval.NewRequestIntent(approval.RequestIntentParams{
				CompilationRequest: request, CandidateSemanticHash: test.candidate,
				ImpactHash: test.impact, AccountSession: proposer,
				AuditReason:         approvalReasonFixture(t, "request independent policy approval"),
				IdempotencyEvidence: approvalProofFixture(t, 1),
			})
			if err != nil {
				t.Fatal(err)
			}
			simulator := &approvalSimulatorFixture{result: simulated}
			transactions := &requestTransactionsFixture{}
			ids := &approvalIDGeneratorFixture{requestIDs: approvalRequestMutationIDsFixture(t)}
			service := approvalServiceFixture(
				t,
				simulator,
				transactions,
				&approvalTransactionsFixture{},
				ids,
				&approvalClockFixture{now: approvalTestTime()},
				&approvalRetryFixture{},
				nil,
				nil,
			)

			_, err = service.Request(t.Context(), intent)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Request() error = %v, want %v", err, test.wantErr)
			}
			if simulator.calls != 1 || transactions.calls != 0 || ids.requestCalls != 0 {
				t.Fatalf(
					"simulator calls=%d transaction calls=%d id calls=%d",
					simulator.calls,
					transactions.calls,
					ids.requestCalls,
				)
			}
		})
	}
}

func TestServiceRejectsSimulatorResultFromAnotherScope(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, _ := approvalSimulationFixture(t, proposer)
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: 2, Rules: []compilation.RuleIntent{},
	})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := approval.NewRequestIntent(approval.RequestIntentParams{
		CompilationRequest:    request,
		CandidateSemanticHash: simulated.ProposedCandidate().SemanticHash(),
		ImpactHash:            simulated.ImpactHash(), AccountSession: proposer,
		AuditReason:         approvalReasonFixture(t, "request independent policy approval"),
		IdempotencyEvidence: approvalProofFixture(t, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	transactions := &requestTransactionsFixture{}
	service := approvalServiceFixture(
		t,
		&approvalSimulatorFixture{result: simulated},
		transactions,
		&approvalTransactionsFixture{},
		&approvalIDGeneratorFixture{requestIDs: approvalRequestMutationIDsFixture(t)},
		&approvalClockFixture{now: approvalTestTime()},
		&approvalRetryFixture{},
		nil,
		nil,
	)

	_, err = service.Request(t.Context(), intent)
	if !errors.Is(err, approval.ErrInvalidBinding) {
		t.Fatalf("Request() error = %v, want ErrInvalidBinding", err)
	}
	if transactions.calls != 0 {
		t.Fatalf("request transactions = %d, want 0", transactions.calls)
	}
}

func TestServiceRejectsAuthorityDriftBetweenSimulationAndProposal(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, request := approvalSimulationFixture(t, proposer)
	transaction := &requestTransactionFixture{
		baselineVector: approvalVectorFixture(t, 12, 7, 8, 1),
	}
	service := approvalServiceFixture(
		t,
		&approvalSimulatorFixture{result: simulated},
		&requestTransactionsFixture{
			transactions: []*requestTransactionFixture{transaction},
		},
		&approvalTransactionsFixture{},
		&approvalIDGeneratorFixture{requestIDs: approvalRequestMutationIDsFixture(t)},
		&approvalClockFixture{now: approvalTestTime()},
		&approvalRetryFixture{},
		nil,
		nil,
	)

	_, err := service.Request(
		t.Context(),
		approvalRequestIntentFixture(t, proposer, simulated, request),
	)
	if !errors.Is(err, approval.ErrImpactChanged) {
		t.Fatalf("Request() error = %v, want ErrImpactChanged", err)
	}
	if transaction.applyCalls != 0 || transaction.commitCalls != 0 ||
		transaction.rollbackCalls != 1 {
		t.Fatalf("transaction = %+v", transaction)
	}
}

func TestServiceRetriesWholeProposalWithStableEvidence(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, request := approvalSimulationFixture(t, proposer)
	first := &requestTransactionFixture{applyErr: approval.ErrRetryableTransaction}
	second := &requestTransactionFixture{}
	transactions := &requestTransactionsFixture{
		transactions: []*requestTransactionFixture{first, second},
	}
	ids := &approvalIDGeneratorFixture{requestIDs: approvalRequestMutationIDsFixture(t)}
	clock := &approvalClockFixture{now: approvalTestTime()}
	retry := &approvalRetryFixture{}
	service := approvalServiceFixture(
		t,
		&approvalSimulatorFixture{result: simulated},
		transactions,
		&approvalTransactionsFixture{},
		ids,
		clock,
		retry,
		nil,
		nil,
	)

	result, err := service.Request(
		t.Context(),
		approvalRequestIntentFixture(t, proposer, simulated, request),
	)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if result.RequestID() != ids.requestIDs.RequestID() || transactions.calls != 2 ||
		ids.requestCalls != 1 || clock.calls != 1 || retry.calls != 1 ||
		first.rollbackCalls != 1 || second.commitCalls != 1 || second.rollbackCalls != 0 {
		t.Fatalf(
			"result=%+v transactions=%+v ids=%+v clock=%+v retry=%+v first=%+v second=%+v",
			result,
			transactions,
			ids,
			clock,
			retry,
			first,
			second,
		)
	}
}

func TestServiceReplaysCompletedProposalWithoutMutation(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, request := approvalSimulationFixture(t, proposer)
	binding, err := approval.NewBindingFromSimulation(simulated)
	if err != nil {
		t.Fatal(err)
	}
	now := approvalTestTime()
	ids := approvalRequestMutationIDsFixture(t)
	completed, err := approval.NewRequestResult(approval.RequestResultParams{
		RequestID: ids.RequestID(), Binding: binding,
		ProposerPrincipalID: proposer.PrincipalID(), ProposerSessionID: proposer.ID(),
		RequestVersion: 1, CreatedAt: now,
		ExpiresAt: now.Add(approval.RequestLifetime),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction := &requestTransactionFixture{completed: completed}
	service := approvalServiceFixture(
		t,
		&approvalSimulatorFixture{result: simulated},
		&requestTransactionsFixture{
			transactions: []*requestTransactionFixture{transaction},
		},
		&approvalTransactionsFixture{},
		&approvalIDGeneratorFixture{requestIDs: ids},
		&approvalClockFixture{now: now},
		&approvalRetryFixture{},
		nil,
		nil,
	)

	result, err := service.Request(
		t.Context(),
		approvalRequestIntentFixture(t, proposer, simulated, request),
	)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if !result.Equal(completed) || transaction.resolveCalls != 1 ||
		transaction.applyCalls != 0 || transaction.commitCalls != 0 ||
		transaction.rollbackCalls != 1 {
		t.Fatalf("result=%+v completed=%+v transaction=%+v", result, completed, transaction)
	}
}

func TestServiceResolvesUnknownProposalCommitByImmutableIdentity(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	simulated, request := approvalSimulationFixture(t, proposer)
	binding, err := approval.NewBindingFromSimulation(simulated)
	if err != nil {
		t.Fatal(err)
	}
	now := approvalTestTime()
	ids := approvalRequestMutationIDsFixture(t)
	committed, err := approval.NewRequestResult(approval.RequestResultParams{
		RequestID: ids.RequestID(), Binding: binding,
		ProposerPrincipalID: proposer.PrincipalID(), ProposerSessionID: proposer.ID(),
		RequestVersion: 1, CreatedAt: now,
		ExpiresAt: now.Add(approval.RequestLifetime),
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction := &requestTransactionFixture{commitErr: approval.ErrCommitOutcomeUnknown}
	resolver := &committedRequestFixture{result: committed, found: true}
	service := approvalServiceFixture(
		t,
		&approvalSimulatorFixture{result: simulated},
		&requestTransactionsFixture{
			transactions: []*requestTransactionFixture{transaction},
		},
		&approvalTransactionsFixture{},
		&approvalIDGeneratorFixture{requestIDs: ids},
		&approvalClockFixture{now: now},
		&approvalRetryFixture{},
		resolver,
		nil,
	)

	result, err := service.Request(
		t.Context(),
		approvalRequestIntentFixture(t, proposer, simulated, request),
	)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if !result.Equal(committed) || resolver.calls != 1 || transaction.applyCalls != 1 ||
		transaction.commitCalls != 1 || transaction.rollbackCalls != 1 {
		t.Fatalf(
			"result=%+v committed=%+v resolver=%+v transaction=%+v",
			result,
			committed,
			resolver,
			transaction,
		)
	}
}

func TestServiceApprovesOnlyWithDistinctActiveHuman(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	approver := approvalSessionFixture(t, 402, 812)
	simulated, _ := approvalSimulationFixture(t, proposer)
	binding, err := approval.NewBindingFromSimulation(simulated)
	if err != nil {
		t.Fatal(err)
	}
	now := approvalTestTime()

	t.Run("distinct approver", func(t *testing.T) {
		t.Parallel()
		transaction := &approvalTransactionFixture{
			binding: binding, proposer: proposer,
			requestExpires: now.Add(approval.RequestLifetime),
		}
		ids := &approvalIDGeneratorFixture{approvalIDs: approvalMutationIDsFixture(t)}
		service := approvalServiceFixture(
			t,
			&approvalSimulatorFixture{},
			&requestTransactionsFixture{},
			&approvalTransactionsFixture{
				transactions: []*approvalTransactionFixture{transaction},
			},
			ids,
			&approvalClockFixture{now: now},
			&approvalRetryFixture{},
			nil,
			nil,
		)

		result, err := service.Approve(t.Context(), approvalCommandFixture(t, binding, approver))
		if err != nil {
			t.Fatalf("Approve() error = %v", err)
		}
		if result.EvidenceID() != ids.approvalIDs.EvidenceID() ||
			result.State() != approval.StateApproved ||
			result.ProposerPrincipalID() != proposer.PrincipalID() ||
			result.ApproverPrincipalID() != approver.PrincipalID() ||
			result.RequestVersion() != 2 || result.EvidenceVersion() != 1 ||
			transaction.resolveCalls != 1 || transaction.applyCalls != 1 ||
			transaction.commitCalls != 1 || transaction.rollbackCalls != 0 {
			t.Fatalf("result=%+v ids=%+v transaction=%+v", result, ids, transaction)
		}
	})

	t.Run("self approval", func(t *testing.T) {
		t.Parallel()
		transaction := &approvalTransactionFixture{
			binding: binding, proposer: proposer,
			requestExpires: now.Add(approval.RequestLifetime),
		}
		service := approvalServiceFixture(
			t,
			&approvalSimulatorFixture{},
			&requestTransactionsFixture{},
			&approvalTransactionsFixture{
				transactions: []*approvalTransactionFixture{transaction},
			},
			&approvalIDGeneratorFixture{approvalIDs: approvalMutationIDsFixture(t)},
			&approvalClockFixture{now: now},
			&approvalRetryFixture{},
			nil,
			nil,
		)

		_, err := service.Approve(t.Context(), approvalCommandFixture(t, binding, proposer))
		if !errors.Is(err, approval.ErrIndependentApproverRequired) {
			t.Fatalf("Approve() error = %v, want ErrIndependentApproverRequired", err)
		}
		if transaction.applyCalls != 0 || transaction.commitCalls != 0 ||
			transaction.rollbackCalls != 1 {
			t.Fatalf("transaction = %+v", transaction)
		}
	})

	t.Run("expired request", func(t *testing.T) {
		t.Parallel()
		transaction := &approvalTransactionFixture{
			binding: binding, proposer: proposer, requestExpires: now,
		}
		service := approvalServiceFixture(
			t,
			&approvalSimulatorFixture{},
			&requestTransactionsFixture{},
			&approvalTransactionsFixture{
				transactions: []*approvalTransactionFixture{transaction},
			},
			&approvalIDGeneratorFixture{approvalIDs: approvalMutationIDsFixture(t)},
			&approvalClockFixture{now: now},
			&approvalRetryFixture{},
			nil,
			nil,
		)

		_, err := service.Approve(t.Context(), approvalCommandFixture(t, binding, approver))
		if !errors.Is(err, approval.ErrRequestExpired) {
			t.Fatalf("Approve() error = %v, want ErrRequestExpired", err)
		}
		if transaction.applyCalls != 0 || transaction.commitCalls != 0 ||
			transaction.rollbackCalls != 1 {
			t.Fatalf("transaction = %+v", transaction)
		}
	})
}

func TestServiceRejectsChangedOrStaleApprovalEvidence(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	approver := approvalSessionFixture(t, 402, 812)
	simulated, _ := approvalSimulationFixture(t, proposer)
	binding, err := approval.NewBindingFromSimulation(simulated)
	if err != nil {
		t.Fatal(err)
	}
	now := approvalTestTime()

	for _, test := range []struct {
		name      string
		version   int64
		candidate publication.SemanticHash
		impact    simulation.ImpactHash
		wantErr   error
	}{
		{
			name: "stale request version", version: 2,
			candidate: binding.CandidateSemanticHash(), impact: binding.ImpactHash(),
			wantErr: approval.ErrRequestVersionConflict,
		},
		{
			name: "candidate changed", version: 1,
			candidate: alternateSemanticHash(t), impact: binding.ImpactHash(),
			wantErr: approval.ErrCandidateChanged,
		},
		{
			name: "impact changed", version: 1,
			candidate: binding.CandidateSemanticHash(), impact: alternateImpactHash(t),
			wantErr: approval.ErrImpactChanged,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command, err := approval.NewCommand(approval.CommandParams{
				Scope: binding.Scope(), RequestID: approvalRequestIDFixture(t, 920),
				ExpectedRequestVersion: test.version,
				CandidateSemanticHash:  test.candidate, ImpactHash: test.impact,
				AccountSession:      approver,
				AuditReason:         approvalReasonFixture(t, "approve unchanged policy impact"),
				IdempotencyEvidence: approvalProofFixture(t, 2),
			})
			if err != nil {
				t.Fatal(err)
			}
			transaction := &approvalTransactionFixture{
				binding: binding, proposer: proposer,
				requestExpires: now.Add(approval.RequestLifetime),
			}
			service := approvalServiceFixture(
				t,
				&approvalSimulatorFixture{},
				&requestTransactionsFixture{},
				&approvalTransactionsFixture{
					transactions: []*approvalTransactionFixture{transaction},
				},
				&approvalIDGeneratorFixture{approvalIDs: approvalMutationIDsFixture(t)},
				&approvalClockFixture{now: now},
				&approvalRetryFixture{},
				nil,
				nil,
			)

			_, err = service.Approve(t.Context(), command)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Approve() error = %v, want %v", err, test.wantErr)
			}
			if transaction.applyCalls != 0 || transaction.commitCalls != 0 ||
				transaction.rollbackCalls != 1 {
				t.Fatalf("transaction = %+v", transaction)
			}
		})
	}
}

func TestServiceReplaysAndRetriesApprovalWithStableEvidence(t *testing.T) {
	t.Parallel()

	proposer := approvalSessionFixture(t, 401, 811)
	approver := approvalSessionFixture(t, 402, 812)
	simulated, _ := approvalSimulationFixture(t, proposer)
	binding, err := approval.NewBindingFromSimulation(simulated)
	if err != nil {
		t.Fatal(err)
	}
	now := approvalTestTime()
	ids := approvalMutationIDsFixture(t)
	command := approvalCommandFixture(t, binding, approver)
	completed, err := approval.NewResult(approval.ResultParams{
		EvidenceID: ids.EvidenceID(), RequestID: command.RequestID(), Binding: binding,
		ProposerPrincipalID: proposer.PrincipalID(), ProposerSessionID: proposer.ID(),
		ApproverPrincipalID: approver.PrincipalID(), ApproverSessionID: approver.ID(),
		RequestVersion: 2, EvidenceVersion: 1, ApprovedAt: now,
		ExpiresAt: now.Add(approval.RequestLifetime),
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("completed replay", func(t *testing.T) {
		t.Parallel()
		transaction := &approvalTransactionFixture{completed: completed}
		service := approvalServiceFixture(
			t,
			&approvalSimulatorFixture{},
			&requestTransactionsFixture{},
			&approvalTransactionsFixture{
				transactions: []*approvalTransactionFixture{transaction},
			},
			&approvalIDGeneratorFixture{approvalIDs: ids},
			&approvalClockFixture{now: now},
			&approvalRetryFixture{},
			nil,
			nil,
		)

		result, err := service.Approve(t.Context(), command)
		if err != nil {
			t.Fatalf("Approve() error = %v", err)
		}
		if !result.Equal(completed) || transaction.applyCalls != 0 ||
			transaction.commitCalls != 0 || transaction.rollbackCalls != 1 {
			t.Fatalf("result=%+v completed=%+v transaction=%+v", result, completed, transaction)
		}
	})

	t.Run("whole transaction retry", func(t *testing.T) {
		t.Parallel()
		first := &approvalTransactionFixture{
			binding: binding, proposer: proposer,
			requestExpires: now.Add(approval.RequestLifetime),
			applyErr:       approval.ErrRetryableTransaction,
		}
		second := &approvalTransactionFixture{
			binding: binding, proposer: proposer,
			requestExpires: now.Add(approval.RequestLifetime),
		}
		transactions := &approvalTransactionsFixture{
			transactions: []*approvalTransactionFixture{first, second},
		}
		generator := &approvalIDGeneratorFixture{approvalIDs: ids}
		clock := &approvalClockFixture{now: now}
		retry := &approvalRetryFixture{}
		service := approvalServiceFixture(
			t,
			&approvalSimulatorFixture{},
			&requestTransactionsFixture{},
			transactions,
			generator,
			clock,
			retry,
			nil,
			nil,
		)

		result, err := service.Approve(t.Context(), command)
		if err != nil {
			t.Fatalf("Approve() error = %v", err)
		}
		if result.EvidenceID() != ids.EvidenceID() || transactions.calls != 2 ||
			generator.approvalCalls != 1 || clock.calls != 1 || retry.calls != 1 ||
			first.rollbackCalls != 1 || second.commitCalls != 1 ||
			second.rollbackCalls != 0 {
			t.Fatalf(
				"result=%+v transactions=%+v generator=%+v clock=%+v retry=%+v first=%+v second=%+v",
				result,
				transactions,
				generator,
				clock,
				retry,
				first,
				second,
			)
		}
	})
}

func alternateSemanticHash(t *testing.T) publication.SemanticHash {
	t.Helper()
	var value [32]byte
	value[0] = 0xff
	hash, err := publication.NewSemanticHash(value)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func alternateImpactHash(t *testing.T) simulation.ImpactHash {
	t.Helper()
	var value [32]byte
	value[0] = 0xfe
	hash, err := simulation.NewImpactHash(value)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
