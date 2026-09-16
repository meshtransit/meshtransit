//go:build integration

package integration

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	adapteroidc "github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func assertPostgreSQLBrowserCallback(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	pool *postgresadapter.Pool,
) {
	t.Helper()
	store, err := postgresadapter.NewAuthTransactionStore(pool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: 10 * time.Second, LockTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	subjects, err := oidcauth.NewSubjectKeyring(
		integrationSubjectKey(t, "integration-subject-active-v1", 0x51),
		integrationSubjectKey(t, "integration-subject-previous-v1", 0x52),
	)
	if err != nil {
		t.Fatal(err)
	}
	sessions := integrationCallbackSessionKeys(t)
	sidID, err := oidcauth.NewDigestKeyID("integration-provider-session-v1")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := oidcauth.NewProviderSessionKey(sidID, integrationFilledBytes(0x62, 32))
	if err != nil {
		t.Fatal(err)
	}
	for index, scenario := range []string{
		"confirmed", "provider error", "provider failure", "missing subject", "missing auth time",
		"unknown claim commit", "unknown issue commit", "canceled after issue commit",
		"issue evidence failure", "unknown failure commit",
	} {
		t.Run("callback "+scenario, func(t *testing.T) {
			params, nonce, startDeps := integrationCallbackStart(
				ctx,
				t,
				store,
				[]string{"ee0", "ee1", "ee2", "ee3", "ee4", "ee5", "ee6", "ee7", "ee8", "ee9"}[index],
			)
			if scenario == "provider error" || scenario == "unknown failure commit" {
				params.Kind, params.Code = oidcauth.CallbackProviderErrorReceived, oidcauth.Code{}
			}
			command, err := oidcauth.NewCallbackCommand(params)
			if err != nil {
				t.Fatal(err)
			}
			claims := &integrationCallbackClaims{base: &integrationClaimTransactions{
				store: store, unknown: scenario == "unknown claim commit",
			}}
			failures := &integrationCallbackFailures{base: &integrationFailureTransactions{
				store: store, unknown: scenario == "unknown failure commit",
			}}
			issues := &integrationIssueTransactions{
				store: store, hideACK: scenario == "unknown issue commit", rejectAfterIssue: scenario == "issue evidence failure",
			}
			request, cancel := context.WithCancel(ctx)
			defer cancel()
			issuePort := &integrationCallbackIssues{base: issues}
			if scenario == "canceled after issue commit" {
				issuePort.afterCommit = cancel
			}
			provider := &integrationCallbackProvider{
				claims: claims, nonce: nonce, fault: scenario,
			}
			service, err := oidcauth.NewCallbackService(oidcauth.CallbackOptions{
				RequestTimeout: 20 * time.Second, FailureTimeout: 5 * time.Second, RollbackTimeout: 2 * time.Second,
				IdleLifetime: time.Minute, AbsoluteLifetime: time.Hour, MaxConcurrent: 2,
			}, oidcauth.CallbackDependencies{
				Pending: store, Claims: claims, Failures: failures, Issues: issuePort,
				IDs: oidcauth.SystemClaimIDs{}, Material: oidcauth.SystemIssueMaterial{},
				Provider: provider, Subjects: store, DigestKey: startDeps.DigestKey,
				VerifierCipher: startDeps.VerifierCipher, SubjectKeys: subjects, SessionKeys: sessions,
				ProviderSessions: sid, Clock: oidcauth.SystemStartClock{}, Observer: adapteroidc.NewCallbackTelemetry(),
				SubjectObserver: adapteroidc.NewSubjectTelemetry(), IssueObserver: adapteroidc.NewIssueTelemetry(),
			})
			if err != nil {
				t.Fatal(err)
			}
			before := authAdmissionAuthorityCounts(ctx, t, admin)
			identityBefore := integrationCallbackIdentityCounts(ctx, t, admin)
			result, callbackErr := service.CompleteBrowser(request, command)
			issued := scenario == "confirmed" || scenario == "unknown issue commit" || scenario == "canceled after issue commit"
			terminal := scenario == "provider error" || scenario == "provider failure" || scenario == "missing subject" ||
				scenario == "unknown failure commit"
			if scenario == "confirmed" {
				if callbackErr != nil || !result.Issued().IsValid() || result.Failure().IsValid() {
					t.Fatalf("whole callback issuance failed: %v", callbackErr)
				}
				assertIssuedSessionAuthenticates(
					ctx,
					t,
					pool,
					sessions,
					result.Issued(),
				)
			} else if scenario == "provider error" {
				if callbackErr != nil || !result.Failure().IsValid() || result.Issued().IsValid() {
					t.Fatal("provider error did not confirm no-grant terminalization")
				}
			} else if callbackErr == nil || !reflect.DeepEqual(result, oidcauth.CallbackResult{}) {
				t.Fatal("failed or unknown callback released evidence")
			}
			if scenario == "unknown claim commit" || scenario == "unknown issue commit" || scenario == "unknown failure commit" {
				if !errors.Is(callbackErr, oidcauth.ErrCommitOutcomeUnknown) {
					t.Fatal("real durable Commit with hidden ACK lost its category")
				}
			}
			if scenario == "canceled after issue commit" && !errors.Is(callbackErr, context.Canceled) {
				t.Fatal("post-commit request cancellation lost")
			}
			wantProvider := 1
			if scenario == "provider error" || scenario == "unknown failure commit" || scenario == "unknown claim commit" {
				wantProvider = 0
			}
			if provider.calls != wantProvider || claims.begins != 1 || claims.isOpen || claims.base.commits != 1 {
				t.Fatal("callback exchanged before closed confirmed claim or duplicated work")
			}
			wantFailures := 0
			if terminal {
				wantFailures = 1
				assertBrowserFailureEvidence(
					ctx,
					t,
					admin,
					failures.base.command,
				)
			}
			if failures.begins != wantFailures || failures.base.commits != wantFailures {
				t.Fatal("callback cleanup inferred non-commit after issuance or lacked erasure")
			}
			wantIssues := 0
			if issued || scenario == "issue evidence failure" {
				wantIssues = 1
			}
			if issues.begins != wantIssues {
				t.Fatal("callback repeated issuance or admitted missing auth_time")
			}
			if issued {
				assertIssueEvidenceChain(
					ctx,
					t,
					admin,
					issues.command,
				)
			}
			if scenario == "unknown claim commit" {
				assertBrowserClaimEvidence(
					ctx,
					t,
					admin,
					claims.base.command,
				)
			}
			integrationCallbackDurableState(
				ctx,
				t,
				admin,
				integrationCallbackExpected{
					claim: claims.base.command, issue: issues.command, before: before,
					identityBefore: identityBefore, issued: issued, terminal: terminal,
				},
			)
			result, err = service.CompleteBrowser(ctx, command)
			countsUnchanged := claims.begins == 1 && provider.calls == wantProvider &&
				issues.begins == wantIssues && failures.begins == wantFailures
			if err == nil || result.IsValid() || !countsUnchanged {
				t.Fatal("same browser input reconstructed a claim/exchange/issuance after durable consumption")
			}
		})
	}
}

func integrationCallbackStart(
	ctx context.Context,
	t *testing.T,
	store *postgresadapter.AuthTransactionStore,
	suffix string,
) (oidcauth.CallbackCommandParams, oidcauth.Nonce, oidcauth.StartDependencies) {
	t.Helper()
	template := integrationAuthTransactionPending(t, integrationAuthRouteParams{
		providerGeneration: 1, recoveryEpoch: 1, workspacePublicID: "01890f00-0000-7000-8000-000000000101",
	}, [4]string{
		"01890f00-0000-7000-8000-000000000" + suffix, "01890f01-0000-7000-8000-000000000" + suffix,
		"01890f02-0000-7000-8000-000000000" + suffix, "01890f03-0000-7000-8000-000000000" + suffix,
	})
	transactions := &integrationAuthStartTransactions{store: store}
	deps := integrationAuthStartDependencies(t, template, store, transactions)
	start, err := oidcauth.NewStartService(oidcauth.StartOptions{
		RequestTimeout: 10 * time.Second, PendingLifetime: 5 * time.Minute,
		RollbackTimeout: 2 * time.Second, ResolveTimeout: 2 * time.Second,
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	started, err := start.Start(ctx, template.Route())
	if err != nil {
		t.Fatal(err)
	}
	location, err := url.Parse(started.AuthorizationRequest().Location())
	if err != nil {
		t.Fatal("invalid synthetic authorization location")
	}
	state, err := oidcauth.ParseState(location.Query().Get("state"))
	if err != nil {
		t.Fatal("invalid synthetic state")
	}
	nonce, err := oidcauth.ParseNonce(location.Query().Get("nonce"))
	if err != nil {
		t.Fatal("invalid synthetic nonce")
	}
	code, err := oidcauth.ParseCode("synthetic-callback-code")
	if err != nil {
		t.Fatal(err)
	}
	return oidcauth.CallbackCommandParams{
		Route: template.Route(), State: state, PreAuthCookie: started.PreAuthCookie(),
		Code: code, Kind: oidcauth.CallbackCodeReceived,
	}, nonce, deps
}

func integrationCallbackSessionKeys(t *testing.T) *accountsession.Keyring {
	t.Helper()
	id, err := accountsession.NewDigestKeyID("integration-session-active-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := accountsession.NewDigestKey(id, integrationFilledBytes(0x61, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := accountsession.NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

type integrationCallbackProvider struct {
	claims *integrationCallbackClaims
	nonce  oidcauth.Nonce
	fault  string
	calls  int
}

func (provider *integrationCallbackProvider) Authenticate(
	ctx context.Context,
	request oidcauth.ExchangeRequest,
) (oidcauth.TokenEvidence, error) {
	provider.calls++
	if provider.claims.isOpen || provider.claims.base.commits != 1 || !request.IsValid() {
		return oidcauth.TokenEvidence{}, errors.New("unconfirmed or open claim unit")
	}
	if _, ok := ctx.Deadline(); !ok {
		return oidcauth.TokenEvidence{}, errors.New("unbounded provider work")
	}
	if provider.fault == "provider failure" {
		return oidcauth.TokenEvidence{}, errors.New("private synthetic provider failure")
	}
	now := time.Now().UTC().Truncate(time.Second)
	authTime, subject := now.Add(-time.Minute), " Exact-é "
	if provider.fault == "missing auth time" {
		authTime = time.Time{}
	}
	if provider.fault == "missing subject" {
		subject = "unbound-synthetic-subject"
	}
	// This is trusted controlled port evidence, NOT live signature/Google proof.
	return oidcauth.NewTokenEvidence(oidcauth.TokenEvidenceParams{
		Issuer: request.Route().Issuer(), Subject: subject, Nonce: provider.nonce,
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), AuthTime: authTime,
		ACR: "urn:meshtransit:assurance:mfa", AMR: []string{"synthetic"},
	})
}

type integrationCallbackClaims struct {
	base   *integrationClaimTransactions
	begins int
	isOpen bool
}

func (owner *integrationCallbackClaims) BeginClaim(
	ctx context.Context,
	route oidcauth.Route,
) (oidcauth.ClaimTransaction, error) {
	owner.begins++
	unit, err := owner.base.BeginClaim(ctx, route)
	if unit == nil {
		return nil, err
	}
	owner.isOpen = true
	return &integrationCallbackClaimUnit{ClaimTransaction: unit, owner: owner}, err
}

type integrationCallbackClaimUnit struct {
	oidcauth.ClaimTransaction
	owner *integrationCallbackClaims
}

func (unit *integrationCallbackClaimUnit) Commit(ctx context.Context) error {
	err := unit.ClaimTransaction.Commit(ctx)
	unit.owner.isOpen = false
	return err
}

func (unit *integrationCallbackClaimUnit) Rollback(ctx context.Context) error {
	err := unit.ClaimTransaction.Rollback(ctx)
	unit.owner.isOpen = false
	return err
}

type integrationCallbackFailures struct {
	base   *integrationFailureTransactions
	begins int
}

func (owner *integrationCallbackFailures) BeginFailure(
	ctx context.Context,
	route oidcauth.Route,
) (oidcauth.FailureTransaction, error) {
	owner.begins++
	return owner.base.BeginFailure(ctx, route)
}

type integrationCallbackIssues struct {
	base        *integrationIssueTransactions
	afterCommit func()
}

func (owner *integrationCallbackIssues) BeginIssue(
	ctx context.Context,
	route oidcauth.Route,
) (oidcauth.IssueTransaction, error) {
	unit, err := owner.base.BeginIssue(ctx, route)
	if unit == nil {
		return nil, err
	}
	return &integrationCallbackIssueUnit{IssueTransaction: unit, owner: owner}, err
}

type integrationCallbackIssueUnit struct {
	oidcauth.IssueTransaction
	owner *integrationCallbackIssues
}

func (unit *integrationCallbackIssueUnit) Commit(ctx context.Context) error {
	if err := unit.IssueTransaction.Commit(ctx); err != nil {
		return err
	}
	if unit.owner.afterCommit != nil {
		unit.owner.afterCommit()
	}
	return nil
}
