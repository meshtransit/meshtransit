package kubecluster

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Install-token approval (V1-12 design §3.3–3.4, schema 309): Core
// approves a replica that joined with an install token, in the name of the
// token's maker, against the cluster's pinned trust; administrators
// confirm, choose or reset that trust.

// ErrTrustDigest reports a digest that is not the trust's (or neither side
// of a contest).
var ErrTrustDigest = errors.New("kubernetes cluster: the digest is not the trust's")

// ErrNoInstallTokenTrust reports a cluster without an install-token trust
// in the state the action needs.
var ErrNoInstallTokenTrust = errors.New("kubernetes cluster: no install-token trust in that state")

// MaxPodTokenLifetime bounds a pod token's remaining life, so its spent jti
// is kept only that long (Core takes tokens of at most 15 minutes); the
// database refuses a later expiry.
const MaxPodTokenLifetime = time.Hour

// podUID is a Kubernetes object UID: a lowercase UUID.
var podUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// jtiPattern is a token ID the database accepts: printable ASCII.
var jtiPattern = regexp.MustCompile(`^[!-~]{1,128}$`)

// PodToken is what Core verified in the pod's ServiceAccount token: the
// pod's UID, the token's ID and when it expires.
type PodToken struct {
	PodUID    string
	JTI       string
	ExpiresAt time.Time
}

// IsValidAt reports a token Core may spend at now.
func (token PodToken) IsValidAt(now time.Time) bool {
	return podUID.MatchString(token.PodUID) && jtiPattern.MatchString(token.JTI) &&
		token.ExpiresAt.After(now) && !token.ExpiresAt.After(now.Add(MaxPodTokenLifetime))
}

// Preapproval asks Core to approve an opened request whose key is an
// install token.
type Preapproval struct {
	KeyID     enrollment.CredentialID
	RequestID RequestID
	Pod       PodToken
}

// PreapprovalOutcome is what the approval did.
type PreapprovalOutcome string

// Preapproval outcomes.
const (
	// PreapprovalApproved: the request is approved; the replica completes.
	PreapprovalApproved PreapprovalOutcome = "approved"
	// PreapprovalContested: the request's trust differs from the cluster's
	// unconfirmed one; the cluster's gateways are suspended and its install
	// tokens revoked until an administrator chooses.
	PreapprovalContested PreapprovalOutcome = "contested"
	// PreapprovalRefused: the request is cancelled (Reason says why).
	PreapprovalRefused PreapprovalOutcome = "refused"
	// PreapprovalNotPreapproved: the key is an ordinary one; the request
	// waits for an administrator.
	PreapprovalNotPreapproved PreapprovalOutcome = "not_preapproved"
)

// Refusal reasons the database gives.
const (
	RefusedInstallTokensOff = "install_tokens_off"
	RefusedTrustContested   = "trust_contested"
	RefusedDiffersFromTrust = "differs_from_trust"
	RefusedPodOrdinal       = "pod_ordinal"
	RefusedTokenUnusable    = "token_unusable"
	RefusedOrdinalUsed      = "ordinal_used"
	RefusedTokenUsed        = "token_used"
	RefusedPodHeld          = "pod_held"
	RefusedApprover         = "approver_unauthorized"
	RefusedTokenReplayed    = "token_replayed"
	RefusedPodTokenExpired  = "pod_token_expired"
)

// KnownRefusal reports a reason the database gives.
func KnownRefusal(reason string) bool {
	switch reason {
	case RefusedInstallTokensOff, RefusedTrustContested, RefusedDiffersFromTrust, RefusedPodOrdinal,
		RefusedTokenUnusable, RefusedOrdinalUsed, RefusedTokenUsed, RefusedPodHeld, RefusedApprover,
		RefusedTokenReplayed, RefusedPodTokenExpired:
		return true
	}
	return false
}

// PreapprovalResult is what an install-token approval did.
type PreapprovalResult struct {
	Outcome PreapprovalOutcome
	Reason  string
	Request ReplicaRequestView
	// TrustPinned is true when this approval pinned the cluster's trust.
	TrustPinned      bool
	SuspendedDevices []publicid.ID
	RevokedTokens    int
}

// PreapprovalStore approves install-token requests.
type PreapprovalStore interface {
	Preapprove(ctx context.Context, preapproval Preapproval) (PreapprovalResult, error)
}

// TrustDecision confirms an unconfirmed trust, or chooses a side of a
// contested one, by the digest the administrator compared.
type TrustDecision struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	Digest        [32]byte
	Version       int64
	CorrelationID publicid.ID
}

// TrustReset removes a cluster's install-token trust and returns it to code
// mode.
type TrustReset struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	Reason        string
	Version       int64
	CorrelationID publicid.ID
}

// TrustDecisionResult is the cluster after a trust action and the gateways
// it changed.
type TrustDecisionResult struct {
	Cluster          Cluster
	Changed          bool
	ResumedDevices   []publicid.ID
	RevokedDevices   []publicid.ID
	SuspendedDevices []publicid.ID
	RevokedTokens    int
}

// TrustStore authorizes and records trust actions.
type TrustStore interface {
	ConfirmTrust(ctx context.Context, decision TrustDecision) (TrustDecisionResult, error)
	ChooseTrust(ctx context.Context, decision TrustDecision) (TrustDecisionResult, error)
	ResetTrust(ctx context.Context, reset TrustReset) (TrustDecisionResult, error)
}

// Trusts confirms, chooses and resets install-token trusts.
type Trusts struct {
	store TrustStore
	clock Clock
}

// NewTrusts requires a store and a clock.
func NewTrusts(store TrustStore, clock Clock) (*Trusts, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Trusts{store: store, clock: clock}, nil
}

func (trusts *Trusts) admit(ctx context.Context, session accountsession.Session, scope network.Scope,
	cluster ID, version int64, correlation publicid.ID) error {
	if ctx == nil || trusts == nil || !scope.IsValid() {
		return ErrInvalid
	}
	now := trusts.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	if !cluster.IsValid() || version <= 0 || !correlation.IsValid() {
		return ErrInvalid
	}
	return nil
}

// Confirm confirms the unconfirmed install-token trust whose digest the
// administrator compared (approve and manage, checked by the store).
func (trusts *Trusts) Confirm(ctx context.Context, decision TrustDecision) (TrustDecisionResult, error) {
	if err := trusts.admit(ctx, decision.Session, decision.Scope, decision.ClusterID, decision.Version,
		decision.CorrelationID); err != nil {
		return TrustDecisionResult{}, err
	}
	if decision.Digest == [32]byte{} {
		return TrustDecisionResult{}, ErrInvalid
	}
	return trusts.store.ConfirmTrust(ctx, decision)
}

// Choose makes the contest's side with this digest the confirmed trust.
func (trusts *Trusts) Choose(ctx context.Context, decision TrustDecision) (TrustDecisionResult, error) {
	if err := trusts.admit(ctx, decision.Session, decision.Scope, decision.ClusterID, decision.Version,
		decision.CorrelationID); err != nil {
		return TrustDecisionResult{}, err
	}
	if decision.Digest == [32]byte{} {
		return TrustDecisionResult{}, ErrInvalid
	}
	return trusts.store.ChooseTrust(ctx, decision)
}

// Reset removes an install-token trust; the cluster goes back to code mode.
func (trusts *Trusts) Reset(ctx context.Context, reset TrustReset) (TrustDecisionResult, error) {
	if err := trusts.admit(ctx, reset.Session, reset.Scope, reset.ClusterID, reset.Version,
		reset.CorrelationID); err != nil {
		return TrustDecisionResult{}, err
	}
	if !ValidResetReason(reset.Reason) {
		return TrustDecisionResult{}, ErrInvalid
	}
	return trusts.store.ResetTrust(ctx, reset)
}

// ValidResetReason reports a reason the database accepts (1 to 256
// characters, no surrounding space) that holds no control character.
func ValidResetReason(reason string) bool {
	length := utf8.RuneCountInString(reason)
	return length >= 1 && length <= 256 && utf8.ValidString(reason) && reason == strings.Trim(reason, " ") &&
		!strings.ContainsFunc(reason, unicode.IsControl)
}
