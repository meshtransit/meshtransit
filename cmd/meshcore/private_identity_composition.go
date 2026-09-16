package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
)

const privateIdentityConstructionTimeout = 5 * time.Second

var errInvalidPrivateIdentityComposition = errors.New("invalid private identity composition")

// This is private root preparation, not a service locator or runtime enablement.
// Future application/browser wiring must share these same resident owners.
type privateIdentityKeys struct {
	initiation, capture, continuation, csrf httpapi.BrowserLoginKey
	transaction                             oidcauth.DigestKey
	verifier                                *oidcauth.VerifierCipher
	subjects                                *oidcauth.SubjectKeyring
	providerSessions                        oidcauth.ProviderSessionKey
	sessions                                *accountsession.Keyring
	idempotency                             *idempotency.Digester
	rateLimit                               *ratelimit.Digester
}

func composePrivateIdentityKeys(ctx context.Context, files *config.PrivateIdentityKeyFiles) (*privateIdentityKeys, error) {
	if ctx == nil || ctx.Err() != nil || files == nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	ctx, cancel := context.WithTimeout(ctx, privateIdentityConstructionTimeout)
	defer cancel()
	material, err := files.Load(ctx)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	defer material.Clear()
	transactionID, err := oidcauth.NewDigestKeyID(material.TransactionDigest.ID)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	transaction, err := oidcauth.NewDigestKey(transactionID, material.TransactionDigest.Bytes[:])
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	verifierID, err := oidcauth.NewVerifierEncryptionKeyID(material.VerifierEncryption.ID)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	verifier, err := oidcauth.NewVerifierCipher(verifierID, material.VerifierEncryption.Bytes[:])
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	subjects, err := composePrivateSubjectKeys(material)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	providerSessionID, err := oidcauth.NewDigestKeyID(material.ProviderSession.ID)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	providerSessions, err := oidcauth.NewProviderSessionKey(providerSessionID, material.ProviderSession.Bytes[:])
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	sessions, err := composePrivateSessionKeys(material)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	idempotencyID, err := idempotency.NewDigestKeyID(material.Idempotency.ID)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	idempotencyKey, err := idempotency.NewDigester(idempotencyID, material.Idempotency.Bytes[:])
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	rateLimitID, err := ratelimit.NewDigestKeyID(material.RateLimit.ID)
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	rateLimitKey, err := ratelimit.NewDigester(rateLimitID, material.RateLimit.Bytes[:])
	if err != nil || ctx.Err() != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	keys := &privateIdentityKeys{
		initiation: privateBrowserKey(material.Initiation), capture: privateBrowserKey(material.Capture),
		continuation: privateBrowserKey(material.Continuation), csrf: privateBrowserKey(material.ManagementCSRF),
		transaction: transaction, verifier: verifier, subjects: subjects, providerSessions: providerSessions,
		sessions: sessions, idempotency: idempotencyKey, rateLimit: rateLimitKey,
	}
	if ctx.Err() != nil {
		clear(keys.initiation.Material)
		clear(keys.capture.Material)
		clear(keys.continuation.Material)
		clear(keys.csrf.Material)
		return nil, errInvalidPrivateIdentityComposition
	}
	return keys, nil
}

func privateBrowserKey(material config.ResidentKeyMaterial) httpapi.BrowserLoginKey {
	return httpapi.BrowserLoginKey{ID: material.ID, Material: bytes.Clone(material.Bytes[:])}
}

func composePrivateSubjectKeys(material *config.PrivateIdentityKeyMaterial) (*oidcauth.SubjectKeyring, error) {
	active, err := privateSubjectKey(material.SubjectActive)
	if err != nil {
		return nil, err
	}
	if material.SubjectPrevious == nil {
		return oidcauth.NewSubjectKeyring(active)
	}
	previous, err := privateSubjectKey(*material.SubjectPrevious)
	if err != nil {
		return nil, err
	}
	return oidcauth.NewSubjectKeyring(active, previous)
}

func privateSubjectKey(material config.ResidentKeyMaterial) (oidcauth.SubjectKey, error) {
	id, err := oidcauth.NewDigestKeyID(material.ID)
	if err != nil {
		return oidcauth.SubjectKey{}, errInvalidPrivateIdentityComposition
	}
	return oidcauth.NewSubjectKey(id, material.Bytes[:])
}

func composePrivateSessionKeys(material *config.PrivateIdentityKeyMaterial) (*accountsession.Keyring, error) {
	active, err := privateSessionKey(material.SessionActive)
	if err != nil {
		return nil, err
	}
	if material.SessionPrevious == nil {
		return accountsession.NewKeyring(active)
	}
	previous, err := privateSessionKey(*material.SessionPrevious)
	if err != nil {
		return nil, err
	}
	return accountsession.NewKeyring(active, previous)
}

func privateSessionKey(material config.ResidentKeyMaterial) (accountsession.DigestKey, error) {
	id, err := accountsession.NewDigestKeyID(material.ID)
	if err != nil {
		return accountsession.DigestKey{}, errInvalidPrivateIdentityComposition
	}
	return accountsession.NewDigestKey(id, material.Bytes[:])
}

func (privateIdentityKeys) String() string   { return "[REDACTED]" }
func (privateIdentityKeys) GoString() string { return "[REDACTED]" }
func (privateIdentityKeys) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}
func (privateIdentityKeys) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}
