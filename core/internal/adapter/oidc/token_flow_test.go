package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// Exercise the actual consumer-owned adapter port, not a constructed request.
// SQL durability/audit remain covered by the separate PostgreSQL claim suite.
func TestConfirmedClaimFlowsThroughRealTokenAuthenticator(t *testing.T) {
	t.Parallel()
	for _, wrongNonce := range []bool{false, true} {
		name := "valid nonce"
		if wrongNonce {
			name = "wrong nonce"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			authenticator := tokenAuthenticator(t, "RS256")
			receipt, secrets, cipher, digest := tokenFlowReceipt(t, authenticator.route)
			key, jwk := tokenKey(t, "RS256")
			claims := tokenClaims(t)
			if !wrongNonce {
				claims["nonce"] = secrets.Nonce().Encoded()
			}
			token := signedToken(t, key, "RS256", claims, nil)
			posts, gets := 0, 0
			authenticator.client = doerFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodPost {
					posts++
					if request.URL.String() != authenticator.route.TokenEndpoint() {
						t.Error("endpoint drift")
					}
					if err := request.ParseForm(); err != nil {
						t.Error(err)
					}
					if request.Form.Get("code_verifier") != secrets.Verifier().Encoded() {
						t.Error("original verifier drift")
					}
					return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{"id_token": token})), nil
				}
				gets++
				return discoveryResponse(200, "application/json", tokenJSON(t, map[string]any{"keys": []any{jwk}})), nil
			})
			service, err := oidcauth.NewExchangeService(oidcauth.ExchangeOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, oidcauth.ExchangeDependencies{Provider: authenticator, Cipher: cipher, DigestKey: digest, Clock: tokenClock{now: tokenNow}})
			if err != nil {
				t.Fatal(err)
			}
			code, _ := tokenCodeVerifier(t)
			result, err := service.ExchangeBrowser(t.Context(), receipt, code)
			if result.IsValid() == wrongNonce || (err == nil) == wrongNonce || posts != 1 || gets != 1 {
				t.Fatal("claim/adapter/Core nonce contract failed")
			}
			if result.IsValid() && result.Identity().Subject() != claims["sub"] {
				t.Fatal("opaque subject changed")
			}
			if result, err := service.ExchangeBrowser(t.Context(), receipt, code); err == nil || result.IsValid() || posts != 1 || gets != 1 {
				t.Fatal("confirmed receipt retried")
			}
		})
	}
}

func TestExchangeCapacityRejectsWithoutQueueAndBurnsExcessReceipt(t *testing.T) {
	t.Parallel()
	route := discoveryRoute(t)
	first, secrets, cipher, digest := tokenFlowReceipt(t, route)
	second, _, _, _ := tokenFlowReceipt(t, route)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseOwner := sync.OnceFunc(func() { close(release) })
	var calls atomic.Int64
	provider := tokenFlowProvider(func(ctx context.Context, _ oidcauth.ExchangeRequest) (oidcauth.TokenEvidence, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return oidcauth.TokenEvidence{}, ctx.Err()
		}
		return oidcauth.NewTokenEvidence(oidcauth.TokenEvidenceParams{Issuer: route.Issuer(), Subject: "opaque", Nonce: secrets.Nonce(), IssuedAt: tokenNow(), ExpiresAt: tokenNow().Add(time.Minute)})
	})
	service, err := oidcauth.NewExchangeService(oidcauth.ExchangeOptions{RequestTimeout: 5 * time.Second, MaxConcurrent: 1}, oidcauth.ExchangeDependencies{Provider: provider, Cipher: cipher, DigestKey: digest, Clock: tokenClock{now: tokenNow}})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := tokenCodeVerifier(t)
	var owner sync.WaitGroup
	var ownerResult oidcauth.ExchangeResult
	var ownerErr error
	t.Cleanup(func() { releaseOwner(); owner.Wait() })
	owner.Go(func() { ownerResult, ownerErr = service.ExchangeBrowser(t.Context(), first, code) })
	select {
	case <-entered:
	case <-t.Context().Done():
		t.Fatal("owner never entered")
	}
	if result, err := service.ExchangeBrowser(t.Context(), second, code); !errors.Is(err, oidcauth.ErrExchangeLimited) || result.IsValid() || calls.Load() != 1 {
		t.Fatal("excess receipt queued or reached provider")
	}
	releaseOwner()
	owner.Wait()
	if ownerErr != nil || !ownerResult.IsValid() {
		t.Fatalf("owner failed: %v", ownerErr)
	}
	if result, err := service.ExchangeBrowser(t.Context(), second, code); !errors.Is(err, oidcauth.ErrExchangeRejected) || result.IsValid() || calls.Load() != 1 {
		t.Fatal("limited receipt became reusable")
	}
}

type tokenFlowProvider func(context.Context, oidcauth.ExchangeRequest) (oidcauth.TokenEvidence, error)

func (provider tokenFlowProvider) Authenticate(ctx context.Context, request oidcauth.ExchangeRequest) (oidcauth.TokenEvidence, error) {
	return provider(ctx, request)
}

func tokenFlowReceipt(t *testing.T, route oidcauth.Route) (oidcauth.ClaimResult, oidcauth.Secrets, *oidcauth.VerifierCipher, oidcauth.DigestKey) {
	t.Helper()
	secrets, err := oidcauth.GenerateSecrets()
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := oidcauth.NewDigestKeyID("synthetic-key.v1")
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	digest, err := oidcauth.NewDigestKey(keyID, material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	cipherKeyID, err := oidcauth.NewVerifierEncryptionKeyID("synthetic-cipher.v1")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherKeyID, material)
	if err != nil {
		t.Fatal(err)
	}
	clear(material)
	metadata, err := oidcauth.NewMetadata(oidcauth.MetadataParams{Issuer: route.Issuer(), AuthorizationEndpoint: route.AuthorizationEndpoint(), TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(), ResponseTypes: []string{"code"}, CodeChallengeMethods: []string{"S256"}, IDTokenSigningAlgorithms: route.AllowedAlgorithms(), TokenAuthMethods: []string{route.ClientAuthMethod()}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	transactionID, err := oidcauth.ParseTransactionID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := oidcauth.NewPending(oidcauth.PendingParams{TransactionID: transactionID, Route: route, Metadata: metadata, Secrets: secrets, DigestKey: digest, VerifierCipher: cipher, MutationIDs: ids, CreatedAt: tokenNow().Add(-time.Second), ExpiresAt: tokenNow().Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := oidcauth.NewPendingSnapshot(oidcauth.PendingSnapshotParams{TransactionID: transactionID, Route: route, Version: 1, State: "pending", FlowKind: "browser_authorization_code", OperationKind: "login", StateDigest: pending.StateDigest(), NonceDigest: pending.NonceDigest(), VerifierCiphertext: pending.VerifierCiphertext(), SemanticHash: pending.SemanticHash(), CreatedAt: pending.CreatedAt(), ExpiresAt: pending.ExpiresAt()})
	if err != nil {
		t.Fatal(err)
	}
	store := &tokenFlowStore{snapshot: snapshot}
	verifier, err := oidcauth.NewBrowserVerificationService(oidcauth.BrowserVerificationOptions{RequestTimeout: time.Second}, oidcauth.BrowserVerificationDependencies{Pending: store, DigestKey: digest, VerifierCipher: cipher, Clock: tokenClock{now: tokenNow}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyBrowser(t.Context(), route, secrets.State(), secrets.PreAuthCookie())
	if err != nil {
		t.Fatal(err)
	}
	claimer, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}, oidcauth.ClaimDependencies{Transactions: store, IDs: oidcauth.SystemClaimIDs{}, Clock: tokenClock{now: tokenNow}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := claimer.ClaimBrowser(t.Context(), verified)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, secrets, cipher, digest
}

type tokenFlowStore struct{ snapshot oidcauth.PendingSnapshot }

func (store *tokenFlowStore) LoadPending(context.Context, oidcauth.Route, oidcauth.Digest) (oidcauth.PendingSnapshot, bool, error) {
	return store.snapshot, true, nil
}
func (store *tokenFlowStore) BeginClaim(context.Context, oidcauth.Route) (oidcauth.ClaimTransaction, error) {
	return store, nil
}
func (store *tokenFlowStore) Claim(_ context.Context, command oidcauth.ClaimCommand) (oidcauth.Claimed, error) {
	return oidcauth.NewClaimed(command.Snapshot(), 2, tokenNow())
}
func (*tokenFlowStore) Commit(context.Context) error   { return nil }
func (*tokenFlowStore) Rollback(context.Context) error { return nil }
