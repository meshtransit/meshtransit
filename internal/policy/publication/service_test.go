package publication_test

import (
	"errors"
	"slices"
	"testing"

	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
)

func TestServicePublishesCandidateAtomically(t *testing.T) {
	t.Parallel()

	command := publicationCommandFixture(t)
	transaction := &publicationTransactionFixture{
		resolution: publicationResolutionFixture(t, command, 5, 1),
	}
	queue := &publicationTransactionQueue{transactions: []*publicationTransactionFixture{transaction}}
	ids := &fixedPublicationMutationIDs{ids: publicationMutationIDsFixture(t, 1)}
	retry := &publicationRetryFixture{}

	result, err := publicationServiceFixture(t, queue, ids, retry, nil).Publish(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Publish() error = %v", err)
	}
	if !result.IsValid() || result.ReleaseID() != ids.ids.ReleaseID() ||
		result.NetworkRevision() != 6 || result.PolicyRevision() != 2 ||
		result.SemanticHash() != command.Candidate().SemanticHash() {
		t.Fatalf("Service.Publish() result = %+v, want committed revision 6/2", result)
	}
	if ids.calls != 1 || !slices.Equal(transaction.calls, []string{"resolve", "apply", "commit"}) ||
		transaction.rollbackCalls != 0 || len(transaction.changes) != 1 {
		t.Fatalf(
			"publication calls: IDs=%d transaction=%v rollbacks=%d changes=%d",
			ids.calls,
			transaction.calls,
			transaction.rollbackCalls,
			len(transaction.changes),
		)
	}
	change := transaction.changes[0]
	if !change.IsValid() || change.OccurredAt() != publicationFixtureTime ||
		!change.MutationIDs().Equal(ids.ids) || change.Command().AuditReason().String() != "phase 1 policy" {
		t.Fatal("publication change did not preserve the validated atomic decision")
	}
}

func TestServiceRejectsStaleBaseWithoutMutation(t *testing.T) {
	t.Parallel()

	command := publicationCommandFixture(t)
	transaction := &publicationTransactionFixture{
		resolution: publicationResolutionFixture(t, command, 8, 2),
	}
	queue := &publicationTransactionQueue{transactions: []*publicationTransactionFixture{transaction}}

	_, err := publicationServiceFixture(
		t,
		queue,
		&fixedPublicationMutationIDs{ids: publicationMutationIDsFixture(t, 1)},
		&publicationRetryFixture{},
		nil,
	).Publish(t.Context(), command)
	if !errors.Is(err, publication.ErrPublicationFailed) ||
		!errors.Is(err, publication.ErrConflict) {
		t.Fatalf("Service.Publish() error = %v, want ErrConflict", err)
	}
	if !slices.Equal(transaction.calls, []string{"resolve", "rollback"}) ||
		len(transaction.changes) != 0 {
		t.Fatalf("stale publication calls = %v changes=%d", transaction.calls, len(transaction.changes))
	}
}

func TestServiceRetriesWholeTransactionWithStableDecision(t *testing.T) {
	t.Parallel()

	command := publicationCommandFixture(t)
	first := &publicationTransactionFixture{
		resolution: publicationResolutionFixture(t, command, 5, 1),
		applyErr:   errors.Join(publication.ErrRetryableTransaction, errPublicationControlled),
	}
	second := &publicationTransactionFixture{
		resolution: publicationResolutionFixture(t, command, 5, 1),
	}
	queue := &publicationTransactionQueue{transactions: []*publicationTransactionFixture{first, second}}
	ids := &fixedPublicationMutationIDs{ids: publicationMutationIDsFixture(t, 1)}
	retry := &publicationRetryFixture{}

	result, err := publicationServiceFixture(t, queue, ids, retry, nil).Publish(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Publish() error = %v", err)
	}
	if !result.IsValid() || ids.calls != 1 || !slices.Equal(retry.calls, []int{1}) ||
		len(first.changes) != 1 || len(second.changes) != 1 ||
		!first.changes[0].MutationIDs().Equal(second.changes[0].MutationIDs()) ||
		first.changes[0].OccurredAt() != second.changes[0].OccurredAt() {
		t.Fatal("whole-transaction retry changed IDs, time, or committed outcome")
	}
}

func TestServiceResolvesUnknownCommitByReleaseIdentity(t *testing.T) {
	t.Parallel()

	command := publicationCommandFixture(t)
	ids := publicationMutationIDsFixture(t, 1)
	want := publicationResultFixture(t, command, ids.ReleaseID(), 6)
	transaction := &publicationTransactionFixture{
		resolution: publicationResolutionFixture(t, command, 5, 1),
		commitErr:  errors.Join(publication.ErrCommitOutcomeUnknown, errPublicationControlled),
	}
	committed := &publicationCommittedFixture{result: want, found: true}

	got, err := publicationServiceFixture(
		t,
		&publicationTransactionQueue{transactions: []*publicationTransactionFixture{transaction}},
		&fixedPublicationMutationIDs{ids: ids},
		&publicationRetryFixture{},
		committed,
	).Publish(t.Context(), command)
	if err != nil {
		t.Fatalf("Service.Publish() error = %v", err)
	}
	if got != want || committed.calls != 1 || committed.releaseID != ids.ReleaseID() {
		t.Fatalf("resolved result = %+v calls=%d, want %+v once", got, committed.calls, want)
	}
}

func TestServiceRejectsInvalidConstructionAndCommand(t *testing.T) {
	t.Parallel()

	if _, err := publication.NewService(publication.Options{}, publication.Dependencies{}); !errors.Is(
		err,
		publication.ErrInvalidService,
	) {
		t.Fatalf("publication.NewService() error = %v, want ErrInvalidService", err)
	}
	service := publicationServiceFixture(
		t,
		&publicationTransactionQueue{},
		&fixedPublicationMutationIDs{},
		&publicationRetryFixture{},
		nil,
	)
	if _, err := service.Publish(t.Context(), publication.Command{}); !errors.Is(
		err,
		publication.ErrInvalidCommand,
	) {
		t.Fatalf("Service.Publish() error = %v, want ErrInvalidCommand", err)
	}
}
