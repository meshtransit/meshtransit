package intake_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var errControlled = errors.New("controlled intake failure")

var intakeTime = time.Date(2026, time.September, 14, 10, 0, 0, 0, time.UTC)

type transactionQueue struct {
	transactions    []*fakeTransaction
	next            int
	beginCalls      int
	beginErr        error
	preparedCommand registration.Command
	preparedHash    registration.RequestHash
	preparedFound   bool
	preparedErr     error
	resolveCalls    int
}

func (queue *transactionQueue) Begin(
	context.Context,
	intake.Lookup,
) (intake.Transaction, error) {
	queue.beginCalls++
	if queue.beginErr != nil {
		return nil, queue.beginErr
	}
	if queue.next >= len(queue.transactions) {
		return nil, errControlled
	}
	transaction := queue.transactions[queue.next]
	queue.next++
	return transaction, nil
}

func (queue *transactionQueue) ResolvePrepared(
	_ context.Context,
	command registration.Command,
) (registration.RequestHash, bool, error) {
	queue.resolveCalls++
	queue.preparedCommand = command
	hash, err := command.RequestHash()
	if err != nil {
		return registration.RequestHash{}, false, err
	}
	queue.preparedHash = hash
	return hash, queue.preparedFound, queue.preparedErr
}

type fakeTransaction struct {
	resolution  intake.Resolution
	resolveErr  error
	applyErr    error
	commitErr   error
	rollbackErr error
	calls       []string
	changes     []intake.Change
}

func (transaction *fakeTransaction) Resolve(
	context.Context,
	intake.Lookup,
) (intake.Resolution, error) {
	transaction.calls = append(transaction.calls, "resolve")
	return transaction.resolution, transaction.resolveErr
}

func (transaction *fakeTransaction) Apply(_ context.Context, change intake.Change) error {
	transaction.calls = append(transaction.calls, "apply")
	transaction.changes = append(transaction.changes, change)
	return transaction.applyErr
}

func (transaction *fakeTransaction) Commit(context.Context) error {
	transaction.calls = append(transaction.calls, "commit")
	return transaction.commitErr
}

func (transaction *fakeTransaction) Rollback(context.Context) error {
	transaction.calls = append(transaction.calls, "rollback")
	return transaction.rollbackErr
}

type validVerifier struct {
	accept bool
}

func (verifier validVerifier) Verify(
	deployment.ID,
	int64,
	enrollment.CredentialToken,
	enrollment.CredentialDigest,
) bool {
	return verifier.accept
}

type recordingVerifier struct {
	accept       bool
	deploymentID deployment.ID
	epoch        int64
	token        enrollment.CredentialToken
	digest       enrollment.CredentialDigest
	calls        int
}

func (verifier *recordingVerifier) Verify(
	deploymentID deployment.ID,
	epoch int64,
	token enrollment.CredentialToken,
	digest enrollment.CredentialDigest,
) bool {
	verifier.calls++
	verifier.deploymentID = deploymentID
	verifier.epoch = epoch
	verifier.token = token
	verifier.digest = digest
	return verifier.accept
}

type fixedEvidenceIDs struct {
	ids   intake.EvidenceIDs
	err   error
	calls int
}

func (generator *fixedEvidenceIDs) NewEvidenceIDs() (intake.EvidenceIDs, error) {
	generator.calls++
	return generator.ids, generator.err
}

type fixedClock struct {
	now time.Time
}

func (clock fixedClock) Now() time.Time { return clock.now }

type noWait struct{}

func (noWait) Wait(context.Context, int) error { return nil }

func newService(
	t *testing.T,
	transactions *transactionQueue,
	verifier intake.CredentialVerifier,
) (*intake.Service, *fixedEvidenceIDs) {
	t.Helper()
	ids := &fixedEvidenceIDs{ids: validEvidenceIDs(t)}
	service, err := intake.NewService(
		intake.Options{
			MaxAttempts:     3,
			RollbackTimeout: time.Second,
			PendingTTL:      10 * time.Minute,
		},
		intake.Dependencies{
			Transactions:     transactions,
			PreparedIntents:  transactions,
			CredentialProofs: verifier,
			EvidenceIDs:      ids,
			Clock:            fixedClock{now: intakeTime},
			Retry:            noWait{},
		},
	)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, ids
}

func validRequest(t *testing.T) intake.Request {
	t.Helper()
	return intake.Request{
		RegistrationID: mustRegistrationID(t, "01890f50-0000-7000-8000-000000000001"),
		CredentialID:   mustCredentialID(t, "01890f50-0000-7000-8000-000000000002"),
		Token:          mustCredentialToken(t),
		Identity:       mustRegistrationIdentity(t),
		Hostname:       mustHostname(t, "node-one.example"),
	}
}

func validAuthority(t *testing.T) intake.Authority {
	t.Helper()
	return authorityWithUsedCount(t, 0)
}

func authorityWithUsedCount(t *testing.T, usedCount int64) intake.Authority {
	t.Helper()
	return authorityWithCredentialState(t, enrollment.CredentialStateActive, usedCount)
}

func authorityWithCredentialState(
	t *testing.T,
	state enrollment.CredentialState,
	usedCount int64,
) intake.Authority {
	t.Helper()
	scope := mustScope(t)
	profileID := mustProfileID(t, "01890f50-0000-7000-8000-000000000003")
	useLimit, err := enrollment.NewBoundedUseLimit(5)
	if err != nil {
		t.Fatalf("NewBoundedUseLimit() error = %v", err)
	}
	profile, err := enrollment.NewProfile(enrollment.ProfileParams{
		ID:                 profileID,
		Scope:              scope,
		State:              enrollment.ProfileStateActive,
		NodeLifetime:       time.Hour,
		EphemeralMode:      enrollment.EphemeralModePersistent,
		CredentialUseLimit: useLimit,
	})
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	issuerID, err := identity.ParsePrincipalID("01890f50-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatalf("ParsePrincipalID() error = %v", err)
	}
	credential, err := enrollment.NewCredential(enrollment.CredentialParams{
		ID:                  mustCredentialID(t, "01890f50-0000-7000-8000-000000000002"),
		ProfileID:           profileID,
		IssuerID:            issuerID,
		State:               state,
		UseLimit:            useLimit,
		UsedCount:           usedCount,
		IssuedRecoveryEpoch: 7,
		ValidFrom:           intakeTime.Add(-time.Hour),
		ExpiresAt:           intakeTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	keyID, err := enrollment.NewDigestKeyID("test-key-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	var digestBytes [32]byte
	for index := range digestBytes {
		digestBytes[index] = 0x5a
	}
	digest, err := enrollment.NewCredentialDigest(keyID, digestBytes)
	if err != nil {
		t.Fatalf("NewCredentialDigest() error = %v", err)
	}
	deploymentID, err := deployment.ParseID("01890f50-0000-7000-8000-000000000005")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	authority, err := intake.NewAuthority(intake.AuthorityParams{
		DeploymentID:  deploymentID,
		Scope:         scope,
		Profile:       profile,
		Credential:    credential,
		Digest:        digest,
		RecoveryEpoch: 7,
	})
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	return authority
}

func authorityResolution(authority intake.Authority) intake.Resolution {
	return intake.NewResolution(authority)
}

func commandFromRequest(
	request intake.Request,
	authority intake.Authority,
	registrationID enrollment.RegistrationID,
) registration.Command {
	return registration.Command{
		RegistrationID: registrationID,
		Scope:          authority.Scope(),
		CredentialID:   request.CredentialID,
		Identity:       request.Identity,
		Hostname:       request.Hostname,
		RecoveryEpoch:  authority.RecoveryEpoch(),
	}
}

func validEvidenceIDs(t *testing.T) intake.EvidenceIDs {
	t.Helper()
	values := []string{
		"01890f50-0000-7000-8000-000000000010",
		"01890f50-0000-7000-8000-000000000011",
		"01890f50-0000-7000-8000-000000000012",
	}
	ids := make([]publicid.ID, len(values))
	for index, value := range values {
		id, err := publicid.Parse(value)
		if err != nil {
			t.Fatalf("publicid.Parse(%q) error = %v", value, err)
		}
		ids[index] = id
	}
	evidence, err := intake.NewEvidenceIDs(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatalf("NewEvidenceIDs() error = %v", err)
	}
	return evidence
}

func mustRegistrationID(t *testing.T, value string) enrollment.RegistrationID {
	t.Helper()
	id, err := enrollment.ParseRegistrationID(value)
	if err != nil {
		t.Fatalf("ParseRegistrationID(%q) error = %v", value, err)
	}
	return id
}

func mustCredentialID(t *testing.T, value string) enrollment.CredentialID {
	t.Helper()
	id, err := enrollment.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("ParseCredentialID(%q) error = %v", value, err)
	}
	return id
}

func mustProfileID(t *testing.T, value string) enrollment.ProfileID {
	t.Helper()
	id, err := enrollment.ParseProfileID(value)
	if err != nil {
		t.Fatalf("ParseProfileID(%q) error = %v", value, err)
	}
	return id
}

func mustCredentialToken(t *testing.T) enrollment.CredentialToken {
	t.Helper()
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	token, err := enrollment.NewCredentialToken(secret)
	if err != nil {
		t.Fatalf("NewCredentialToken() error = %v", err)
	}
	return token
}

func mustRegistrationIdentity(t *testing.T) node.RegistrationIdentity {
	t.Helper()
	var machineBytes, nodeBytes [32]byte
	for index := range machineBytes {
		machineBytes[index] = 0x21
		nodeBytes[index] = 0x22
	}
	machineKey, err := node.NewMachineKey(machineBytes)
	if err != nil {
		t.Fatalf("NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey(nodeBytes)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	value, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatalf("NewRegistrationIdentity() error = %v", err)
	}
	return value
}

func mustHostname(t *testing.T, value string) node.Hostname {
	t.Helper()
	hostname, err := node.ParseHostname(value)
	if err != nil {
		t.Fatalf("ParseHostname(%q) error = %v", value, err)
	}
	return hostname
}

func mustScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f50-0000-7000-8000-000000000006")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f50-0000-7000-8000-000000000007")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func containsSecret(message string, secret string) bool {
	return secret != "" && strings.Contains(message, secret)
}
