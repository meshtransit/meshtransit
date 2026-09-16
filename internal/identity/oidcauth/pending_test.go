package oidcauth

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestNewPendingPreparesBoundedDurableEvidence(t *testing.T) {
	t.Parallel()

	pending, verifierCipher := pendingFixture(t)
	if !pending.IsValid() {
		t.Fatal("NewPending() returned invalid evidence")
	}
	if pending.StateDigest().Bytes() == pending.NonceDigest().Bytes() {
		t.Fatal("state and nonce durable evidence share one digest domain")
	}
	binding, err := pending.Route().Binding(pending.TransactionID())
	if err != nil {
		t.Fatalf("Route.Binding() error = %v", err)
	}
	verifier, err := verifierCipher.Open(binding, pending.VerifierCiphertext())
	if err != nil {
		t.Fatalf("VerifierCipher.Open() error = %v", err)
	}
	if verifier.Encoded() != secretFixture(t).Verifier().Encoded() {
		t.Fatal("encrypted verifier did not preserve exact PKCE evidence")
	}
	if !pending.AuthorizationRequest().IsValid() ||
		pending.SemanticHash() == ([32]byte{}) {
		t.Fatal("pending transaction omitted redirect or semantic evidence")
	}
	if got := fmt.Sprint(pending); got != "[REDACTED]" {
		t.Fatalf("fmt.Sprint(Pending) = %q, want redacted", got)
	}
	if value := pending.LogValue(); value.Kind() != slog.KindString || value.String() != "[REDACTED]" {
		t.Fatal("Pending.LogValue() did not redact")
	}
}

func TestNewPendingRejectsUnsafeLifetimeAndAliasedIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*PendingParams)
	}{
		{
			name: "excessive lifetime",
			mutate: func(params *PendingParams) {
				params.ExpiresAt = params.CreatedAt.Add(maximumPendingLifetime + time.Nanosecond)
			},
		},
		{
			name: "mutation aliases transaction",
			mutate: func(params *PendingParams) {
				transactionID := publicid.ID(params.TransactionID)
				params.MutationIDs = mustMutationIDs(
					t,
					transactionID,
					mustPublicID(t, "01890f00-0000-7000-8000-000000000007"),
					mustPublicID(t, "01890f00-0000-7000-8000-000000000008"),
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := pendingParamsFixture(t)
			test.mutate(&params)
			_, err := NewPending(params)
			if !errors.Is(err, ErrInvalidPending) {
				t.Fatalf("NewPending() error = %v, want ErrInvalidPending", err)
			}
		})
	}
}

func TestNewPendingCanonicalizesTimeAndRejectsAliasedEvidenceIDs(t *testing.T) {
	t.Parallel()

	params := pendingParamsFixture(t)
	params.CreatedAt = params.CreatedAt.Add(789 * time.Nanosecond)
	params.ExpiresAt = params.ExpiresAt.Add(789 * time.Nanosecond)
	pending, err := NewPending(params)
	if err != nil {
		t.Fatalf("NewPending() error = %v", err)
	}
	if pending.CreatedAt().Nanosecond()%1000 != 0 || pending.ExpiresAt().Nanosecond()%1000 != 0 {
		t.Fatal("pending timestamps exceed PostgreSQL microsecond precision")
	}
	pending.mutationIDs = mustMutationIDs(
		t,
		publicid.ID(pending.TransactionID()),
		mustPublicID(t, "01890f00-0000-7000-8000-000000000017"),
		mustPublicID(t, "01890f00-0000-7000-8000-000000000018"),
	)
	if pending.IsValid() {
		t.Fatal("pending binding accepted an evidence identity aliased to the transaction")
	}
}

func TestNewCreatedValidatesDurableEvidence(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.September, 16, 3, 0, 0, 0, time.UTC)
	transactionID := mustTransactionID(t, "01890f00-0000-7000-8000-000000000005")
	created, err := NewCreated(transactionID, 1, createdAt, createdAt.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("NewCreated() error = %v", err)
	}
	if !created.IsValid() || created.TransactionID() != transactionID || created.Version() != 1 {
		t.Fatal("NewCreated() changed durable identity or version")
	}
	if _, err := NewCreated(transactionID, 2, createdAt, createdAt.Add(5*time.Minute)); !errors.Is(err, ErrInvalidCreated) {
		t.Fatalf("NewCreated(version=2) error = %v, want ErrInvalidCreated", err)
	}
}

func pendingFixture(t *testing.T) (Pending, *VerifierCipher) {
	t.Helper()
	params := pendingParamsFixture(t)
	pending, err := NewPending(params)
	if err != nil {
		t.Fatalf("NewPending() error = %v", err)
	}
	return pending, params.VerifierCipher
}

func pendingParamsFixture(t *testing.T) PendingParams {
	t.Helper()
	digestKeyID, err := NewDigestKeyID("oidc-digest-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	digestKey, err := NewDigestKey(digestKeyID, bytes.Repeat([]byte{0x6a}, 32))
	if err != nil {
		t.Fatalf("NewDigestKey() error = %v", err)
	}
	encryptionKeyID, err := NewVerifierEncryptionKeyID("oidc-aead-v1")
	if err != nil {
		t.Fatalf("NewVerifierEncryptionKeyID() error = %v", err)
	}
	verifierCipher, err := newVerifierCipher(
		encryptionKeyID,
		bytes.Repeat([]byte{0x7b}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x8c}, 12)),
	)
	if err != nil {
		t.Fatalf("newVerifierCipher() error = %v", err)
	}
	createdAt := time.Date(2026, time.September, 16, 3, 0, 0, 0, time.UTC)
	return PendingParams{
		TransactionID:  mustTransactionID(t, "01890f00-0000-7000-8000-000000000005"),
		Route:          routeFixture(t),
		Metadata:       metadataFixture(t),
		Secrets:        secretFixture(t),
		DigestKey:      digestKey,
		VerifierCipher: verifierCipher,
		MutationIDs: mustMutationIDs(
			t,
			mustPublicID(t, "01890f00-0000-7000-8000-000000000006"),
			mustPublicID(t, "01890f00-0000-7000-8000-000000000007"),
			mustPublicID(t, "01890f00-0000-7000-8000-000000000008"),
		),
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(5 * time.Minute),
	}
}

func mustMutationIDs(
	t *testing.T,
	changeID publicid.ID,
	auditEventID publicid.ID,
	outboxEventID publicid.ID,
) MutationIDs {
	t.Helper()
	ids, err := NewMutationIDs(MutationIDParams{
		ChangeID:      changeID,
		AuditEventID:  auditEventID,
		OutboxEventID: outboxEventID,
	})
	if err != nil {
		t.Fatalf("NewMutationIDs() error = %v", err)
	}
	return ids
}

func mustPublicID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}
