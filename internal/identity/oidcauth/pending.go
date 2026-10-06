package oidcauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"time"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

const (
	maximumPendingLifetime = 10 * time.Minute
	pendingHashDomain      = "meshtransit/oidc-auth/pending/v2\x00"
)

var (
	// ErrInvalidMutationIDs reports missing or aliased audit/outbox identities.
	ErrInvalidMutationIDs = errors.New("oidc auth: invalid mutation ids")
	// ErrInvalidPending reports incomplete or unsafe durable transaction material.
	ErrInvalidPending = errors.New("oidc auth: invalid pending transaction")
	// ErrInvalidCreated reports malformed durable creation evidence.
	ErrInvalidCreated = errors.New("oidc auth: invalid created transaction")
)

// MutationIDParams names the immutable evidence created with one AuthTransaction.
type MutationIDParams struct {
	ChangeID      publicid.ID
	AuditEventID  publicid.ID
	OutboxEventID publicid.ID
}

// MutationIDs is one distinct set reused after an uncertain commit.
type MutationIDs struct {
	changeID      publicid.ID
	auditEventID  publicid.ID
	outboxEventID publicid.ID
}

// NewMutationIDs validates that every evidence identity is a distinct UUIDv7.
func NewMutationIDs(params MutationIDParams) (MutationIDs, error) {
	values := [...]publicid.ID{params.ChangeID, params.AuditEventID, params.OutboxEventID}
	for index, value := range values {
		if !value.IsValid() {
			return MutationIDs{}, ErrInvalidMutationIDs
		}
		for previous := range index {
			if value == values[previous] {
				return MutationIDs{}, ErrInvalidMutationIDs
			}
		}
	}
	return MutationIDs{
		changeID:      params.ChangeID,
		auditEventID:  params.AuditEventID,
		outboxEventID: params.OutboxEventID,
	}, nil
}

// ChangeID returns the authority-mutation correlation identity.
func (ids MutationIDs) ChangeID() publicid.ID { return ids.changeID }

// AuditEventID returns the append-only audit event identity.
func (ids MutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns the durable event identity.
func (ids MutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IsValid reports whether all evidence identities remain distinct.
func (ids MutationIDs) IsValid() bool {
	validated, err := NewMutationIDs(MutationIDParams{
		ChangeID:      ids.changeID,
		AuditEventID:  ids.auditEventID,
		OutboxEventID: ids.outboxEventID,
	})
	return err == nil && validated == ids
}

// PendingParams contains the exact inputs prepared before the short database transaction.
type PendingParams struct {
	TransactionID  TransactionID
	Route          Route
	Metadata       Metadata
	Secrets        Secrets
	DigestKey      DigestKey
	VerifierCipher *VerifierCipher
	MutationIDs    MutationIDs
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// Pending is an immutable browser authorization transaction ready for persistence.
// It contains no raw PKCE verifier, but its authorization request remains secret-bearing.
type Pending struct {
	transactionID        TransactionID
	route                Route
	stateDigest          Digest
	nonceDigest          Digest
	verifierCiphertext   Ciphertext
	mutationIDs          MutationIDs
	createdAt            time.Time
	expiresAt            time.Time
	authorizationRequest AuthorizationRequest
	semanticHash         [sha256.Size]byte
}

// NewPending constructs all secret-derived evidence before opening a database transaction.
func NewPending(params PendingParams) (Pending, error) {
	rawCreatedAt := params.CreatedAt.UTC()
	rawExpiresAt := params.ExpiresAt.UTC()
	rawLifetimeInvalid := rawCreatedAt.IsZero() || rawExpiresAt.IsZero() ||
		!rawExpiresAt.After(rawCreatedAt) ||
		rawExpiresAt.Sub(rawCreatedAt) > maximumPendingLifetime
	// PostgreSQL timestamptz persists microsecond precision. Canonicalizing before
	// hashing keeps uncertain-commit evidence byte-for-byte stable after reload.
	createdAt := rawCreatedAt.Truncate(time.Microsecond)
	expiresAt := rawExpiresAt.Truncate(time.Microsecond)
	invalidLifetime := createdAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(createdAt) ||
		expiresAt.Sub(createdAt) > maximumPendingLifetime || rawLifetimeInvalid
	transactionPublicID := publicid.ID(params.TransactionID)
	idsAliasTransaction := transactionPublicID == params.MutationIDs.ChangeID() ||
		transactionPublicID == params.MutationIDs.AuditEventID() ||
		transactionPublicID == params.MutationIDs.OutboxEventID()
	if !params.TransactionID.IsValid() || !params.Route.IsValid() ||
		!params.Metadata.IsValid() || !params.Secrets.IsValid() ||
		!params.DigestKey.isValid() || params.VerifierCipher == nil ||
		!params.VerifierCipher.ID().IsValid() || !params.MutationIDs.IsValid() ||
		invalidLifetime || idsAliasTransaction {
		return Pending{}, ErrInvalidPending
	}
	authorizationRequest, err := NewAuthorizationRequest(
		params.Route,
		params.Metadata,
		params.Secrets,
	)
	if err != nil {
		return Pending{}, errors.Join(ErrInvalidPending, err)
	}
	stateDigest, err := params.DigestKey.State(
		params.Route.DeploymentID(),
		params.Route.RecoveryEpoch(),
		params.Secrets.State(),
	)
	if err != nil {
		return Pending{}, errors.Join(ErrInvalidPending, err)
	}
	nonceDigest, err := params.DigestKey.Nonce(
		params.Route.DeploymentID(),
		params.Route.RecoveryEpoch(),
		params.Secrets.Nonce(),
	)
	if err != nil {
		return Pending{}, errors.Join(ErrInvalidPending, err)
	}
	binding, err := params.Route.Binding(params.TransactionID)
	if err != nil {
		return Pending{}, errors.Join(ErrInvalidPending, err)
	}
	cookieDigest, err := params.DigestKey.PreAuthCookie(binding, params.Secrets.PreAuthCookie())
	if err != nil {
		return Pending{}, errors.Join(ErrInvalidPending, err)
	}
	verifierCiphertext, err := params.VerifierCipher.SealBrowser(
		binding,
		params.Secrets.Verifier(),
		cookieDigest,
	)
	if err != nil {
		return Pending{}, errors.Join(ErrInvalidPending, err)
	}
	pending := Pending{
		transactionID:        params.TransactionID,
		route:                params.Route,
		stateDigest:          stateDigest,
		nonceDigest:          nonceDigest,
		verifierCiphertext:   verifierCiphertext,
		mutationIDs:          params.MutationIDs,
		createdAt:            createdAt,
		expiresAt:            expiresAt,
		authorizationRequest: authorizationRequest,
	}
	pending.semanticHash = hashPending(pending)
	if !pending.IsValid() {
		return Pending{}, ErrInvalidPending
	}
	return pending, nil
}

// TransactionID returns the stable single-use transaction identity.
func (pending Pending) TransactionID() TransactionID { return pending.transactionID }

// Route returns the exact immutable trust route.
func (pending Pending) Route() Route { return pending.route }

// StateDigest returns durable state lookup evidence.
func (pending Pending) StateDigest() Digest { return pending.stateDigest }

// NonceDigest returns durable ID-token nonce evidence.
func (pending Pending) NonceDigest() Digest { return pending.nonceDigest }

// VerifierCiphertext returns a defensive copy of encrypted PKCE material.
func (pending Pending) VerifierCiphertext() Ciphertext {
	ciphertext, err := NewCiphertext(
		pending.verifierCiphertext.KeyID(),
		pending.verifierCiphertext.Bytes(),
	)
	if err != nil {
		return Ciphertext{}
	}
	return ciphertext
}

// MutationIDs returns immutable audit/outbox identities.
func (pending Pending) MutationIDs() MutationIDs { return pending.mutationIDs }

// CreatedAt returns the stable preparation time used across retries.
func (pending Pending) CreatedAt() time.Time { return pending.createdAt }

// ExpiresAt returns the bounded absolute transaction deadline.
func (pending Pending) ExpiresAt() time.Time { return pending.expiresAt }

// AuthorizationRequest returns the secret-bearing exact provider redirect.
func (pending Pending) AuthorizationRequest() AuthorizationRequest {
	return pending.authorizationRequest
}

// SemanticHash returns non-plaintext integrity evidence for audit binding.
func (pending Pending) SemanticHash() [sha256.Size]byte { return pending.semanticHash }

// IsValid reports whether all prepared evidence is complete and mutually bound.
func (pending Pending) IsValid() bool {
	invalidLifetime := pending.createdAt.IsZero() || pending.expiresAt.IsZero() ||
		!pending.expiresAt.After(pending.createdAt) ||
		pending.expiresAt.Sub(pending.createdAt) > maximumPendingLifetime
	transactionPublicID := publicid.ID(pending.transactionID)
	idsAliasTransaction := transactionPublicID == pending.mutationIDs.ChangeID() ||
		transactionPublicID == pending.mutationIDs.AuditEventID() ||
		transactionPublicID == pending.mutationIDs.OutboxEventID()
	return pending.transactionID.IsValid() && pending.route.IsValid() &&
		pending.stateDigest.IsValid() && pending.nonceDigest.IsValid() &&
		pending.stateDigest != pending.nonceDigest && pending.verifierCiphertext.IsValid() &&
		pending.mutationIDs.IsValid() && pending.authorizationRequest.IsValid() &&
		pending.semanticHash != ([sha256.Size]byte{}) && !invalidLifetime && !idsAliasTransaction &&
		hashPending(pending) == pending.semanticHash
}

// String prevents accidental authorization-request or ciphertext disclosure.
func (Pending) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed transaction disclosure.
func (Pending) GoString() string { return "oidcauth.Pending([REDACTED])" }

// LogValue prevents accidental structured-log transaction disclosure.
func (Pending) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Created is durable evidence that one pending transaction was inserted.
type Created struct {
	transactionID TransactionID
	version       int64
	createdAt     time.Time
	expiresAt     time.Time
}

// NewCreated validates durable creation evidence returned by PostgreSQL.
func NewCreated(
	transactionID TransactionID,
	version int64,
	createdAt time.Time,
	expiresAt time.Time,
) (Created, error) {
	created := Created{
		transactionID: transactionID,
		version:       version,
		createdAt:     createdAt.UTC(),
		expiresAt:     expiresAt.UTC(),
	}
	if !created.IsValid() {
		return Created{}, ErrInvalidCreated
	}
	return created, nil
}

// TransactionID returns the created transaction identity.
func (created Created) TransactionID() TransactionID { return created.transactionID }

// Version returns the durable aggregate version.
func (created Created) Version() int64 { return created.version }

// CreatedAt returns the authoritative stored creation time.
func (created Created) CreatedAt() time.Time { return created.createdAt }

// ExpiresAt returns the authoritative stored expiry time.
func (created Created) ExpiresAt() time.Time { return created.expiresAt }

// IsValid reports whether durable creation evidence is internally consistent.
func (created Created) IsValid() bool {
	return created.transactionID.IsValid() && created.version == 1 &&
		!created.createdAt.IsZero() && created.expiresAt.After(created.createdAt) &&
		created.expiresAt.Sub(created.createdAt) <= maximumPendingLifetime
}

func hashPending(pending Pending) [sha256.Size]byte {
	var encoded bytes.Buffer
	writePendingField(&encoded, []byte(pendingHashDomain))
	transactionID := pending.transactionID.Bytes()
	writePendingField(&encoded, transactionID[:])
	route := pending.route
	deploymentID := route.DeploymentID().Bytes()
	providerID := route.ProviderID().Bytes()
	clientID := route.ClientID().Bytes()
	writePendingField(&encoded, deploymentID[:])
	writePendingField(&encoded, providerID[:])
	writePendingField(&encoded, clientID[:])
	for _, value := range []string{
		route.Issuer(), route.DiscoveryURI(), route.AuthorizationEndpoint(),
		route.TokenEndpoint(), route.JWKSURI(), route.OIDCClientID(),
		route.ClientAuthMethod(), route.RedirectID(), route.RedirectURI(),
		route.ReturnRouteID(), pending.stateDigest.Algorithm(),
		pending.stateDigest.KeyID().String(), pending.nonceDigest.Algorithm(),
		pending.nonceDigest.KeyID().String(), pending.verifierCiphertext.Algorithm(),
		pending.verifierCiphertext.KeyID().String(),
	} {
		writePendingField(&encoded, []byte(value))
	}
	writePendingField(&encoded, []byte(route.ConnectorID()))
	for _, value := range route.Scopes() {
		writePendingField(&encoded, []byte(value))
	}
	writePendingField(&encoded, nil)
	for _, value := range route.AllowedAlgorithms() {
		writePendingField(&encoded, []byte(value))
	}
	writePendingField(&encoded, nil)
	stateDigest := pending.stateDigest.Bytes()
	nonceDigest := pending.nonceDigest.Bytes()
	writePendingField(&encoded, stateDigest[:])
	writePendingField(&encoded, nonceDigest[:])
	writePendingField(&encoded, pending.verifierCiphertext.Bytes())
	var number [binary.MaxVarintLen64]byte
	for _, value := range []int64{
		route.ProviderGeneration(), route.RecoveryEpoch(),
		pending.createdAt.UnixNano(), pending.expiresAt.UnixNano(),
	} {
		length := binary.PutVarint(number[:], value)
		writePendingField(&encoded, number[:length])
	}
	return sha256.Sum256(encoded.Bytes())
}

func writePendingField(buffer *bytes.Buffer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	buffer.Write(length[:])
	buffer.Write(value)
}
