package kubecluster

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Install tokens (V1-12 design §3.1–3.2): a cluster in private_tofu mode
// takes preapproved join keys, so a one-command install needs no code typed
// per replica. Schema 307.

var (
	// ErrInstallTokensOff reports a cluster that is not in private_tofu
	// mode: it takes no install token.
	ErrInstallTokensOff = errors.New("kubernetes cluster: the cluster does not take install tokens")
	// ErrTrustAnchored reports a trust mode change on a cluster that already
	// trusts signing keys: reset its trust first.
	ErrTrustAnchored = errors.New("kubernetes cluster: the cluster already trusts signing keys")
	// ErrInstallTokenTrust reports approval by code or pasted keys on a
	// cluster that is not in code mode: only an install token anchors its
	// trust.
	ErrInstallTokenTrust = errors.New("kubernetes cluster: only an install token anchors this cluster's trust")
	// ErrTrustContested reports a cluster whose install-token trust is
	// contested: an administrator chooses first.
	ErrTrustContested = errors.New("kubernetes cluster: the cluster's trust is contested")
)

// TrustMode is how a cluster anchors its first signing keys.
type TrustMode string

const (
	// TrustModeCode anchors them with the first replica an administrator
	// approves by its code (K1).
	TrustModeCode TrustMode = "code"
	// TrustModePrivateTOFU anchors them with the first replica an install
	// token admits, unconfirmed until an administrator confirms its digest.
	TrustModePrivateTOFU TrustMode = "private_tofu"
)

// IsKnown reports a mode a cluster can be set to.
func (mode TrustMode) IsKnown() bool { return mode == TrustModeCode || mode == TrustModePrivateTOFU }

// Install token bounds (design Q-V12-3): an hour by default, 24 hours at
// most, one replica per use up to five.
const (
	DefaultInstallTokenLifetime = time.Hour
	MinInstallTokenLifetime     = 5 * time.Minute
	MaxInstallTokenLifetime     = 24 * time.Hour
	MaxInstallTokenReplicas     = 5
)

// ValidInstallToken reports a lifetime in whole seconds within the bounds
// and a replica count of 1 to MaxInstallTokenReplicas.
func ValidInstallToken(lifetime time.Duration, replicas int) bool {
	return lifetime >= MinInstallTokenLifetime && lifetime <= MaxInstallTokenLifetime &&
		lifetime%time.Second == 0 && replicas >= 1 && replicas <= MaxInstallTokenReplicas
}

// TrustModeChange asks to set a cluster's trust mode; Version is the
// cluster's version the person saw (If-Match).
type TrustModeChange struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	Mode          TrustMode
	Version       int64
	CorrelationID publicid.ID
}

// TrustModeResult is the cluster after a change, its mode, whether it
// changed and how many install tokens leaving private_tofu revoked.
type TrustModeResult struct {
	Cluster       Cluster
	Mode          TrustMode
	Changed       bool
	RevokedTokens int
}

// InstallTokenRequest asks for an install token of a cluster.
type InstallTokenRequest struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	Lifetime      time.Duration
	Replicas      int
	CorrelationID publicid.ID
}

// InstallTokenIssue is what the store records: the request with the new
// key's identifiers and secret.
type InstallTokenIssue struct {
	InstallTokenRequest
	KeyID         enrollment.CredentialID
	PreapprovalID publicid.ID
	Token         enrollment.CredentialToken
}

// IssuedInstallToken is the stored key, the replicas it covers and its
// one-time presentation.
type IssuedInstallToken struct {
	Key          JoinKey
	Replicas     int
	Presentation enrollment.JoinKeyPresentation
}

// InstallTokenStore authorizes and records trust modes and install tokens.
type InstallTokenStore interface {
	SetTrustMode(ctx context.Context, change TrustModeChange) (TrustModeResult, error)
	IssueInstallToken(ctx context.Context, issue InstallTokenIssue) (JoinKey, error)
}

// InstallTokens sets trust modes and issues install tokens.
type InstallTokens struct {
	store   InstallTokenStore
	clock   Clock
	secrets Secrets
}

// NewInstallTokens requires a store, a clock and a secret source.
func NewInstallTokens(store InstallTokenStore, clock Clock, secrets Secrets) (*InstallTokens, error) {
	if store == nil || clock == nil || secrets == nil {
		return nil, ErrInvalid
	}
	return &InstallTokens{store: store, clock: clock, secrets: secrets}, nil
}

func (tokens *InstallTokens) admit(ctx context.Context, session accountsession.Session, scope network.Scope) error {
	if ctx == nil || tokens == nil || !scope.IsValid() {
		return ErrInvalid
	}
	now := tokens.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// SetTrustMode sets a cluster's trust mode (approve and manage, checked by
// the store).
func (tokens *InstallTokens) SetTrustMode(ctx context.Context, change TrustModeChange) (TrustModeResult, error) {
	if err := tokens.admit(ctx, change.Session, change.Scope); err != nil {
		return TrustModeResult{}, err
	}
	if !change.ClusterID.IsValid() || !change.Mode.IsKnown() || change.Version <= 0 ||
		!change.CorrelationID.IsValid() {
		return TrustModeResult{}, ErrInvalid
	}
	return tokens.store.SetTrustMode(ctx, change)
}

// Issue creates an install token and returns it with its one-time
// presentation.
func (tokens *InstallTokens) Issue(ctx context.Context, request InstallTokenRequest) (IssuedInstallToken, error) {
	if err := tokens.admit(ctx, request.Session, request.Scope); err != nil {
		return IssuedInstallToken{}, err
	}
	if request.Lifetime == 0 {
		request.Lifetime = DefaultInstallTokenLifetime
	}
	if !request.ClusterID.IsValid() || !ValidInstallToken(request.Lifetime, request.Replicas) ||
		!request.CorrelationID.IsValid() {
		return IssuedInstallToken{}, ErrInvalid
	}
	token, err := tokens.secrets.NewToken()
	if err != nil {
		return IssuedInstallToken{}, ErrUnavailable
	}
	keyID, err := tokens.secrets.NewCredentialID()
	if err != nil {
		return IssuedInstallToken{}, ErrUnavailable
	}
	preapprovalID, err := publicid.New()
	if err != nil {
		return IssuedInstallToken{}, ErrUnavailable
	}
	presentation, err := enrollment.NewJoinKeyPresentation(keyID, token)
	if err != nil {
		return IssuedInstallToken{}, ErrUnavailable
	}
	key, err := tokens.store.IssueInstallToken(ctx, InstallTokenIssue{
		InstallTokenRequest: request, KeyID: keyID, PreapprovalID: preapprovalID, Token: token,
	})
	if err != nil {
		return IssuedInstallToken{}, err
	}
	return IssuedInstallToken{Key: key, Replicas: request.Replicas, Presentation: presentation}, nil
}
