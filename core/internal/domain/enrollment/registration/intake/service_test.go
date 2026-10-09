package intake_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
)

func TestServicePreparesPendingIntentFromServerAuthority(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	authority := validAuthority(t)
	transaction := &fakeTransaction{resolution: intake.NewResolution(authority)}
	transactions := &transactionQueue{transactions: []*fakeTransaction{transaction}}
	verifier := &recordingVerifier{accept: true}
	service, ids := newService(t, transactions, verifier)

	command, err := service.Prepare(t.Context(), request)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if command.Scope != authority.Scope() || command.RecoveryEpoch != authority.RecoveryEpoch() {
		t.Fatalf("Prepare() authority = (%v, %d), want server-derived (%v, %d)",
			command.Scope,
			command.RecoveryEpoch,
			authority.Scope(),
			authority.RecoveryEpoch(),
		)
	}
	if command.RegistrationID != request.RegistrationID || command.CredentialID != request.CredentialID ||
		command.Identity != request.Identity || command.Hostname != request.Hostname {
		t.Fatalf("Prepare() command = %+v, want authenticated request semantics", command)
	}
	if got, want := transaction.calls, []string{"resolve", "apply", "commit"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction calls = %v, want %v", got, want)
	}
	if len(transaction.changes) != 1 {
		t.Fatalf("applied changes = %d, want 1", len(transaction.changes))
	}
	change := transaction.changes[0]
	if change.Command() != command || change.Registration().Scope() != authority.Scope() ||
		change.Registration().ProfileID() != authority.Profile().ID() ||
		change.Registration().State() != enrollment.RegistrationStatePending {
		t.Fatalf("applied change does not preserve authenticated authority")
	}
	if change.EvidenceIDs() != ids.ids || ids.calls != 1 {
		t.Fatalf("evidence IDs = (%+v, calls %d), want one stable set", change.EvidenceIDs(), ids.calls)
	}
	if got, want := change.Registration().ExpiresAt(), authority.Credential().ExpiresAt(); !got.Equal(want) {
		t.Fatalf("pending expiry = %v, want credential-bounded %v", got, want)
	}
	if verifier.calls != 1 || verifier.deploymentID != authority.DeploymentID() ||
		verifier.epoch != authority.Credential().IssuedRecoveryEpoch() ||
		verifier.token != request.Token || verifier.digest != authority.Digest() {
		t.Fatal("credential verifier did not receive the exact server-owned digest context")
	}
}

func TestServiceRejectsCredentialProofWithoutMutation(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	transaction := &fakeTransaction{resolution: intake.NewResolution(validAuthority(t))}
	transactions := &transactionQueue{transactions: []*fakeTransaction{transaction}}
	service, ids := newService(t, transactions, validVerifier{accept: false})

	_, err := service.Prepare(t.Context(), request)
	if !errors.Is(err, intake.ErrAuthenticationFailed) {
		t.Fatalf("Prepare() error = %v, want authentication failure", err)
	}
	if got, want := transaction.calls, []string{"resolve", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction calls = %v, want %v", got, want)
	}
	if ids.calls != 0 || len(transaction.changes) != 0 {
		t.Fatalf("rejected proof generated IDs or mutation: ids=%d changes=%d", ids.calls, len(transaction.changes))
	}
	if containsSecret(err.Error(), request.Token.Reveal()) {
		t.Fatal("authentication error disclosed bearer token")
	}
}

func TestServiceHidesCredentialLookupFailure(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	transactions := &transactionQueue{
		beginErr: errors.Join(
			intake.ErrCredentialRejected,
			errors.New(request.Token.Reveal()),
		),
	}
	service, ids := newService(t, transactions, validVerifier{accept: true})

	_, err := service.Prepare(t.Context(), request)
	if !errors.Is(err, intake.ErrAuthenticationFailed) {
		t.Fatalf("Prepare() error = %v, want authentication failure", err)
	}
	if containsSecret(err.Error(), request.Token.Reveal()) {
		t.Fatal("credential lookup failure disclosed bearer token")
	}
	if ids.calls != 0 {
		t.Fatalf("evidence ID calls = %d, want 0", ids.calls)
	}
}

func TestServiceReplaysCanonicalPendingIntentWithoutMutation(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	authority := validAuthority(t)
	canonicalID := mustRegistrationID(t, "01890f50-0000-7000-8000-000000000099")
	canonical := commandFromRequest(request, authority, canonicalID)
	hash, err := canonical.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	resolution, err := intake.NewExistingResolution(authority, canonicalID, hash)
	if err != nil {
		t.Fatalf("NewExistingResolution() error = %v", err)
	}
	transaction := &fakeTransaction{resolution: resolution}
	transactions := &transactionQueue{transactions: []*fakeTransaction{transaction}}
	service, ids := newService(t, transactions, validVerifier{accept: true})

	command, err := service.Prepare(t.Context(), request)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if command.RegistrationID != canonicalID {
		t.Fatalf("Prepare() registration ID = %v, want canonical %v", command.RegistrationID, canonicalID)
	}
	if got, want := transaction.calls, []string{"resolve", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction calls = %v, want %v", got, want)
	}
	if ids.calls != 0 || len(transaction.changes) != 0 {
		t.Fatalf("replay generated IDs or mutation: ids=%d changes=%d", ids.calls, len(transaction.changes))
	}
}

func TestServiceReplaysCommittedIntentAfterCredentialQuotaConsumed(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	authority := authorityWithUsedCount(t, 5)
	canonicalID := mustRegistrationID(t, "01890f50-0000-7000-8000-000000000099")
	canonical := commandFromRequest(request, authority, canonicalID)
	hash, err := canonical.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	resolution, err := intake.NewExistingResolution(authority, canonicalID, hash)
	if err != nil {
		t.Fatalf("NewExistingResolution() error = %v", err)
	}
	transaction := &fakeTransaction{resolution: resolution}
	service, ids := newService(
		t,
		&transactionQueue{transactions: []*fakeTransaction{transaction}},
		validVerifier{accept: true},
	)

	command, err := service.Prepare(t.Context(), request)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if command != canonical {
		t.Fatalf("Prepare() command = %+v, want committed canonical command", command)
	}
	if got, want := transaction.calls, []string{"resolve", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction calls = %v, want %v", got, want)
	}
	if ids.calls != 0 || len(transaction.changes) != 0 {
		t.Fatalf("committed replay generated IDs or mutation: ids=%d changes=%d", ids.calls, len(transaction.changes))
	}
}

func TestServiceDoesNotReplayCommittedIntentWithRevokedCredential(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	authority := authorityWithCredentialState(t, enrollment.CredentialStateRevoked, 5)
	canonicalID := mustRegistrationID(t, "01890f50-0000-7000-8000-000000000099")
	canonical := commandFromRequest(request, authority, canonicalID)
	hash, err := canonical.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	resolution, err := intake.NewExistingResolution(authority, canonicalID, hash)
	if err != nil {
		t.Fatalf("NewExistingResolution() error = %v", err)
	}
	transaction := &fakeTransaction{resolution: resolution}
	service, ids := newService(
		t,
		&transactionQueue{transactions: []*fakeTransaction{transaction}},
		validVerifier{accept: true},
	)

	_, err = service.Prepare(t.Context(), request)
	if !errors.Is(err, intake.ErrAuthenticationFailed) {
		t.Fatalf("Prepare() error = %v, want authentication failure", err)
	}
	if got, want := transaction.calls, []string{"resolve", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction calls = %v, want %v", got, want)
	}
	if ids.calls != 0 || len(transaction.changes) != 0 {
		t.Fatalf("revoked replay generated IDs or mutation: ids=%d changes=%d", ids.calls, len(transaction.changes))
	}
}

func TestServiceRejectsConflictingPendingIntent(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	authority := validAuthority(t)
	canonicalID := mustRegistrationID(t, "01890f50-0000-7000-8000-000000000099")
	conflicting := commandFromRequest(request, authority, canonicalID)
	conflicting.Hostname = mustHostname(t, "different.example")
	hash, err := conflicting.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	resolution, err := intake.NewExistingResolution(authority, canonicalID, hash)
	if err != nil {
		t.Fatalf("NewExistingResolution() error = %v", err)
	}
	transaction := &fakeTransaction{resolution: resolution}
	service, ids := newService(
		t,
		&transactionQueue{transactions: []*fakeTransaction{transaction}},
		validVerifier{accept: true},
	)

	_, err = service.Prepare(t.Context(), request)
	if !errors.Is(err, registration.ErrIntentConflict) {
		t.Fatalf("Prepare() error = %v, want intent conflict", err)
	}
	if got, want := transaction.calls, []string{"resolve", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction calls = %v, want %v", got, want)
	}
	if ids.calls != 0 {
		t.Fatalf("conflict evidence ID calls = %d, want 0", ids.calls)
	}
}

func TestServiceRetriesWholeTransactionWithStableDecision(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	authority := validAuthority(t)
	first := &fakeTransaction{
		resolution: authorityResolution(authority),
		applyErr:   intake.ErrRetryableTransaction,
	}
	second := &fakeTransaction{resolution: authorityResolution(authority)}
	transactions := &transactionQueue{transactions: []*fakeTransaction{first, second}}
	service, ids := newService(t, transactions, validVerifier{accept: true})

	if _, err := service.Prepare(t.Context(), request); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(first.changes) != 1 || len(second.changes) != 1 {
		t.Fatalf("applied change counts = (%d, %d), want one per attempt", len(first.changes), len(second.changes))
	}
	if first.changes[0] != second.changes[0] {
		t.Fatal("whole-transaction retry changed the durable decision")
	}
	if ids.calls != 1 {
		t.Fatalf("evidence ID calls = %d, want 1 across retry", ids.calls)
	}
	if got, want := first.calls, []string{"resolve", "apply", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first transaction calls = %v, want %v", got, want)
	}
	if got, want := second.calls, []string{"resolve", "apply", "commit"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("second transaction calls = %v, want %v", got, want)
	}
}

func TestServiceResolvesUnknownCommitBySemanticHash(t *testing.T) {
	t.Parallel()

	request := validRequest(t)
	transaction := &fakeTransaction{
		resolution: authorityResolution(validAuthority(t)),
		commitErr:  intake.ErrCommitOutcomeUnknown,
	}
	transactions := &transactionQueue{
		transactions:  []*fakeTransaction{transaction},
		preparedFound: true,
	}
	service, _ := newService(t, transactions, validVerifier{accept: true})

	command, err := service.Prepare(t.Context(), request)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	wantHash, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	if transactions.preparedCommand != command || transactions.preparedHash != wantHash ||
		transactions.resolveCalls != 1 {
		t.Fatalf("commit resolver did not verify the exact prepared command")
	}
}

func TestServiceValidatesDependenciesRequestAndContext(t *testing.T) {
	t.Parallel()

	if _, err := intake.NewService(intake.Options{}, intake.Dependencies{}); !errors.Is(err, intake.ErrInvalidService) {
		t.Fatalf("NewService() error = %v, want invalid service", err)
	}
	transactions := &transactionQueue{}
	service, _ := newService(t, transactions, validVerifier{accept: true})
	if _, err := service.Prepare(t.Context(), intake.Request{}); !errors.Is(err, intake.ErrInvalidRequest) {
		t.Fatalf("Prepare(invalid) error = %v, want invalid request", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.Prepare(canceled, validRequest(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Prepare(canceled) error = %v, want context cancellation", err)
	}
	if transactions.beginCalls != 0 {
		t.Fatalf("Begin() calls = %d, want 0 for invalid inputs", transactions.beginCalls)
	}
}
