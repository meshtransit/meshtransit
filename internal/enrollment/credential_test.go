package enrollment_test

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/identity"
)

func TestNewCredential(t *testing.T) {
	t.Parallel()

	credential := mustCredential(t, enrollment.CredentialStateActive, 0, mustBoundedLimit(t, 1))
	if credential.ID() != mustCredentialID(t) || credential.ProfileID() != mustProfileID(t) ||
		credential.IssuerID() != mustIssuerID(t) ||
		credential.State() != enrollment.CredentialStateActive || credential.UsedCount() != 0 ||
		credential.IssuedRecoveryEpoch() != 7 || !credential.ValidFrom().Equal(testTime()) ||
		!credential.ExpiresAt().Equal(testTime().Add(time.Hour)) {
		t.Fatal("NewCredential() did not preserve durable state")
	}
}

func TestNewCredentialRejectsInvalidState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*enrollment.CredentialParams)
	}{
		{name: "missing credential id", mutate: func(params *enrollment.CredentialParams) { params.ID = enrollment.CredentialID{} }},
		{name: "missing profile id", mutate: func(params *enrollment.CredentialParams) { params.ProfileID = enrollment.ProfileID{} }},
		{name: "missing issuer id", mutate: func(params *enrollment.CredentialParams) { params.IssuerID = identity.PrincipalID{} }},
		{name: "unknown lifecycle", mutate: func(params *enrollment.CredentialParams) { params.State = enrollment.CredentialStateUnknown }},
		{name: "unknown use policy", mutate: func(params *enrollment.CredentialParams) { params.UseLimit = enrollment.UseLimit{} }},
		{name: "negative used count", mutate: func(params *enrollment.CredentialParams) { params.UsedCount = -1 }},
		{name: "used count exceeds quota", mutate: func(params *enrollment.CredentialParams) { params.UsedCount = 2 }},
		{name: "missing recovery epoch", mutate: func(params *enrollment.CredentialParams) { params.IssuedRecoveryEpoch = 0 }},
		{name: "missing validity start", mutate: func(params *enrollment.CredentialParams) { params.ValidFrom = time.Time{} }},
		{name: "non increasing validity", mutate: func(params *enrollment.CredentialParams) { params.ExpiresAt = params.ValidFrom }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			params := validCredentialParams(t, mustBoundedLimit(t, 1))
			test.mutate(&params)
			if _, err := enrollment.NewCredential(params); !errors.Is(err, enrollment.ErrInvalidCredential) {
				t.Fatalf("NewCredential() error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestCredentialConsume(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		state         enrollment.CredentialState
		usedCount     int64
		limit         enrollment.UseLimit
		now           time.Time
		recoveryEpoch int64
		wantErr       error
	}{
		{name: "one-off available", state: enrollment.CredentialStateActive, limit: mustBoundedLimit(t, 1), now: testTime(), recoveryEpoch: 7},
		{name: "reusable available", state: enrollment.CredentialStateActive, usedCount: 100, limit: enrollment.NewUnlimitedUseLimit(), now: testTime(), recoveryEpoch: 7},
		{name: "revoked", state: enrollment.CredentialStateRevoked, limit: mustBoundedLimit(t, 1), now: testTime(), recoveryEpoch: 7, wantErr: enrollment.ErrCredentialInactive},
		{name: "missing current time", state: enrollment.CredentialStateActive, limit: mustBoundedLimit(t, 1), recoveryEpoch: 7, wantErr: enrollment.ErrInvalidCredential},
		{name: "stale recovery epoch", state: enrollment.CredentialStateActive, limit: mustBoundedLimit(t, 1), now: testTime(), recoveryEpoch: 6, wantErr: enrollment.ErrRecoveryEpochMismatch},
		{name: "before validity", state: enrollment.CredentialStateActive, limit: mustBoundedLimit(t, 1), now: testTime().Add(-time.Nanosecond), recoveryEpoch: 7, wantErr: enrollment.ErrCredentialNotYetValid},
		{name: "at expiry", state: enrollment.CredentialStateActive, limit: mustBoundedLimit(t, 1), now: testTime().Add(time.Hour), recoveryEpoch: 7, wantErr: enrollment.ErrCredentialExpired},
		{name: "quota exhausted", state: enrollment.CredentialStateActive, usedCount: 1, limit: mustBoundedLimit(t, 1), now: testTime(), recoveryEpoch: 7, wantErr: enrollment.ErrCredentialExhausted},
		{name: "counter exhausted", state: enrollment.CredentialStateActive, usedCount: int64(^uint64(0) >> 1), limit: enrollment.NewUnlimitedUseLimit(), now: testTime(), recoveryEpoch: 7, wantErr: enrollment.ErrCredentialExhausted},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			credential := mustCredential(t, test.state, test.usedCount, test.limit)
			consumed, err := credential.Consume(test.now, test.recoveryEpoch)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Consume() error = %v, want %v", err, test.wantErr)
				}
				if credential.UsedCount() != test.usedCount {
					t.Fatal("failed Consume() mutated the original credential")
				}
				return
			}
			if err != nil {
				t.Fatalf("Consume() error = %v", err)
			}
			if consumed.UsedCount() != test.usedCount+1 || credential.UsedCount() != test.usedCount {
				t.Fatal("Consume() did not return an isolated incremented value")
			}
		})
	}
}

func TestCredentialRevoke(t *testing.T) {
	t.Parallel()

	credential := mustCredential(t, enrollment.CredentialStateActive, 0, mustBoundedLimit(t, 1))
	revoked, err := credential.Revoke()
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	revoked, err = revoked.Revoke()
	if err != nil {
		t.Fatalf("repeated Revoke() error = %v", err)
	}
	if revoked.State() != enrollment.CredentialStateRevoked ||
		credential.State() != enrollment.CredentialStateActive {
		t.Fatal("Revoke() is not immutable and idempotent")
	}
	if _, err := (enrollment.Credential{}).Revoke(); !errors.Is(err, enrollment.ErrInvalidCredential) {
		t.Fatalf("zero Revoke() error = %v, want ErrInvalidCredential", err)
	}
}

func mustCredential(
	t *testing.T,
	state enrollment.CredentialState,
	usedCount int64,
	limit enrollment.UseLimit,
) enrollment.Credential {
	t.Helper()

	params := validCredentialParams(t, limit)
	params.State = state
	params.UsedCount = usedCount
	credential, err := enrollment.NewCredential(params)
	if err != nil {
		t.Fatalf("NewCredential() error = %v", err)
	}
	return credential
}

func validCredentialParams(t *testing.T, limit enrollment.UseLimit) enrollment.CredentialParams {
	t.Helper()

	return enrollment.CredentialParams{
		ID:                  mustCredentialID(t),
		ProfileID:           mustProfileID(t),
		IssuerID:            mustIssuerID(t),
		State:               enrollment.CredentialStateActive,
		UseLimit:            limit,
		IssuedRecoveryEpoch: 7,
		ValidFrom:           testTime(),
		ExpiresAt:           testTime().Add(time.Hour),
	}
}

func mustBoundedLimit(t *testing.T, maximum int64) enrollment.UseLimit {
	t.Helper()

	limit, err := enrollment.NewBoundedUseLimit(maximum)
	if err != nil {
		t.Fatalf("NewBoundedUseLimit() error = %v", err)
	}
	return limit
}

func mustCredentialID(t *testing.T) enrollment.CredentialID {
	t.Helper()

	id, err := enrollment.ParseCredentialID("01890f00-0000-7000-8000-000000000402")
	if err != nil {
		t.Fatalf("ParseCredentialID() error = %v", err)
	}
	return id
}

func mustProfileID(t *testing.T) enrollment.ProfileID {
	t.Helper()

	id, err := enrollment.ParseProfileID("01890f00-0000-7000-8000-000000000401")
	if err != nil {
		t.Fatalf("ParseProfileID() error = %v", err)
	}
	return id
}

func mustIssuerID(t *testing.T) identity.PrincipalID {
	t.Helper()

	id, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatalf("ParsePrincipalID() error = %v", err)
	}
	return id
}

func testTime() time.Time {
	return time.Date(2026, 9, 13, 7, 0, 0, 0, time.UTC)
}
