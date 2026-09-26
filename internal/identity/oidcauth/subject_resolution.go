package oidcauth

import (
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidSubjectResolution rejects unsafe construction before effects.
	ErrInvalidSubjectResolution = errors.New("oidc auth: invalid subject resolution")
	// ErrSubjectResolutionRejected conceals absent, ambiguous or stale admission.
	ErrSubjectResolutionRejected = errors.New("oidc auth: subject resolution rejected")
	// ErrSubjectResolutionUnavailable conceals dependency or read completion failure.
	ErrSubjectResolutionUnavailable = errors.New("oidc auth: subject resolution unavailable")
	// ErrSubjectResolutionLimited bounds concurrent resolution without queueing.
	ErrSubjectResolutionLimited = errors.New("oidc auth: subject resolution limited")
)

// LoginMembershipID identifies one exact Workspace membership in a login snapshot.
type LoginMembershipID publicid.ID

// ParseLoginMembershipID validates a canonical membership public UUIDv7.
func ParseLoginMembershipID(value string) (LoginMembershipID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return LoginMembershipID{}, ErrSubjectResolutionRejected
	}
	return LoginMembershipID(id), nil
}

// String returns the public membership identity, never an internal sequence ID.
func (id LoginMembershipID) String() string { return publicid.ID(id).String() }

// IsValid rejects an absent membership identity.
func (id LoginMembershipID) IsValid() bool { return publicid.ID(id).IsValid() }

// SubjectLookup contains original consuming evidence and at most two HMACs.
// It has no raw subject or provider-token field and grants no access.
type SubjectLookup struct {
	claimed Claimed
	digests []SubjectDigest
}

// NewSubjectLookup validates and copies a trusted read query, not an issuance grant.
func NewSubjectLookup(claimed Claimed, digests []SubjectDigest) (SubjectLookup, error) {
	query := SubjectLookup{claimed: claimed, digests: slices.Clone(digests)}
	if !query.IsValid() {
		return SubjectLookup{}, ErrInvalidSubjectResolution
	}
	return query, nil
}

// Claimed returns immutable original consuming evidence for exact SQL comparison.
func (query SubjectLookup) Claimed() Claimed { return query.claimed }

// Snapshot returns the immutable original creation binding, never raw subject.
func (query SubjectLookup) Snapshot() PendingSnapshot { return query.claimed.snapshot }

// Digests returns a copy of the bounded, ordered candidates for persistence.
func (query SubjectLookup) Digests() []SubjectDigest { return slices.Clone(query.digests) }

// IsValid checks shape, not proof of cryptographic or current membership validity.
func (query SubjectLookup) IsValid() bool {
	if !query.claimed.IsValid() || len(query.digests) < 1 || len(query.digests) > 2 {
		return false
	}
	if query.claimed.snapshot.Route().ClientAuthMethod() != "client_secret_basic" {
		return false
	}
	for _, digest := range query.digests {
		if !digest.IsValid() {
			return false
		}
	}
	return len(query.digests) == 1 || query.digests[0].KeyID() != query.digests[1].KeyID()
}

// String redacts claim and identity lookup evidence.
func (SubjectLookup) String() string { return "[REDACTED]" }

// GoString redacts detailed identity lookup evidence.
func (SubjectLookup) GoString() string { return "oidcauth.SubjectLookup([REDACTED])" }

// LogValue redacts structured identity lookup evidence.
func (SubjectLookup) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// LoginSubjectParams is trusted persistence output; constructors confer no grant.
type LoginSubjectParams struct {
	Lookup                                                                                SubjectLookup
	Digest                                                                                SubjectDigest
	PrincipalID                                                                           identity.PrincipalID
	IdentitySubjectID                                                                     accountsession.IdentitySubjectID
	MembershipID                                                                          LoginMembershipID
	SubjectVersion, AccountVersion, MembershipVersion                                     int64
	PrincipalAuthorityGeneration, AccountSessionGeneration, MembershipAuthorityGeneration int64
	EvaluatedAt, MembershipExpiresAt                                                      time.Time
}

// String redacts loaded identity/membership evidence.
func (LoginSubjectParams) String() string { return "[REDACTED]" }

// GoString redacts detailed loaded identity/membership evidence.
func (LoginSubjectParams) GoString() string { return "oidcauth.LoginSubjectParams([REDACTED])" }

// LogValue redacts structured loaded identity/membership evidence.
func (LoginSubjectParams) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// LoginSubjectSnapshot is immutable read evidence, never final Session authority.
// A later write must independently lock and recheck route/identity/membership/CAS.
type LoginSubjectSnapshot struct{ params LoginSubjectParams }

// NewLoginSubjectSnapshot validates exact metadata without rounding durable times.
func NewLoginSubjectSnapshot(params LoginSubjectParams) (LoginSubjectSnapshot, error) {
	params.Lookup.digests = slices.Clone(params.Lookup.digests)
	snapshot := LoginSubjectSnapshot{params: params}
	if !snapshot.IsValid() {
		return LoginSubjectSnapshot{}, ErrSubjectResolutionRejected
	}
	return snapshot, nil
}

// PrincipalID returns the stable Account Principal resolved by exact subject.
func (snapshot LoginSubjectSnapshot) PrincipalID() identity.PrincipalID {
	return snapshot.params.PrincipalID
}

// IdentitySubjectID returns the unique existing provider-subject binding.
func (snapshot LoginSubjectSnapshot) IdentitySubjectID() accountsession.IdentitySubjectID {
	return snapshot.params.IdentitySubjectID
}

// MembershipID returns only the exact login Workspace's existing membership.
func (snapshot LoginSubjectSnapshot) MembershipID() LoginMembershipID {
	return snapshot.params.MembershipID
}

// SubjectVersion returns the optimistic stable-binding version, not a grant.
func (snapshot LoginSubjectSnapshot) SubjectVersion() int64 { return snapshot.params.SubjectVersion }

// AccountVersion returns the optimistic Account version, not a grant.
func (snapshot LoginSubjectSnapshot) AccountVersion() int64 { return snapshot.params.AccountVersion }

// MembershipVersion returns the optimistic exact membership version, not a grant.
func (snapshot LoginSubjectSnapshot) MembershipVersion() int64 {
	return snapshot.params.MembershipVersion
}

// PrincipalAuthorityGeneration returns the observed Principal authority fence.
func (snapshot LoginSubjectSnapshot) PrincipalAuthorityGeneration() int64 {
	return snapshot.params.PrincipalAuthorityGeneration
}

// AccountSessionGeneration returns the observed Account-wide session fence.
func (snapshot LoginSubjectSnapshot) AccountSessionGeneration() int64 {
	return snapshot.params.AccountSessionGeneration
}

// MembershipAuthorityGeneration returns the observed exact membership fence.
func (snapshot LoginSubjectSnapshot) MembershipAuthorityGeneration() int64 {
	return snapshot.params.MembershipAuthorityGeneration
}

// EvaluatedAt returns the canonical live database decision time.
func (snapshot LoginSubjectSnapshot) EvaluatedAt() time.Time { return snapshot.params.EvaluatedAt }

// MembershipExpiresAt returns the exclusive membership deadline; zero means absent.
func (snapshot LoginSubjectSnapshot) MembershipExpiresAt() time.Time {
	return snapshot.params.MembershipExpiresAt
}

// Digest returns a copy of the matched versioned HMAC for the trusted write seam.
func (snapshot LoginSubjectSnapshot) Digest() SubjectDigest { return snapshot.params.Digest }

// IsValid checks shape and bounded exact match, not current membership authority.
func (snapshot LoginSubjectSnapshot) IsValid() bool {
	p := snapshot.params
	validIDs := p.PrincipalID.IsValid() && p.IdentitySubjectID.IsValid() && p.MembershipID.IsValid()
	validVersions := p.SubjectVersion > 0 && p.AccountVersion > 0 && p.MembershipVersion > 0
	validGenerations := p.PrincipalAuthorityGeneration > 0 && p.AccountSessionGeneration > 0 && p.MembershipAuthorityGeneration > 0
	if !validIDs || !validVersions || !validGenerations || !p.Lookup.IsValid() {
		return false
	}
	if !canonicalSubjectTime(p.EvaluatedAt) || !liveClaim(p.Lookup.claimed, p.EvaluatedAt) {
		return false
	}
	if !p.MembershipExpiresAt.IsZero() && (!canonicalSubjectTime(p.MembershipExpiresAt) || !p.EvaluatedAt.Before(p.MembershipExpiresAt)) {
		return false
	}
	return subjectCandidateMatches(p.Lookup.digests, p.Digest)
}

// Matches rejects substituted original claim or digest evidence after a read.
func (snapshot LoginSubjectSnapshot) Matches(query SubjectLookup) bool {
	if !snapshot.IsValid() || !query.IsValid() {
		return false
	}
	original := snapshot.params.Lookup.claimed
	if original.TransactionID() != query.claimed.TransactionID() || !original.ConsumedAt().Equal(query.claimed.ConsumedAt()) {
		return false
	}
	before, after := original.snapshot.SemanticHash(), query.claimed.snapshot.SemanticHash()
	return hmac.Equal(before[:], after[:]) && subjectCandidateMatches(query.digests, snapshot.params.Digest)
}

// String redacts Account and Workspace membership evidence.
func (LoginSubjectSnapshot) String() string { return "[REDACTED]" }

// GoString redacts detailed Account and membership evidence.
func (LoginSubjectSnapshot) GoString() string { return "oidcauth.LoginSubjectSnapshot([REDACTED])" }

// LogValue redacts structured Account and membership evidence.
func (LoginSubjectSnapshot) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func canonicalSubjectTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1000 == 0
}

func subjectCandidateMatches(candidates []SubjectDigest, target SubjectDigest) bool {
	if !target.IsValid() {
		return false
	}
	matched := false
	actual := target.Bytes()
	for _, candidate := range candidates {
		expected := candidate.Bytes()
		equal := hmac.Equal(actual[:], expected[:])
		matched = matched || (candidate.KeyID() == target.KeyID() && equal)
	}
	return matched
}

// LoginSubjectResolver closes its bounded read-only resources before returning.
// It cannot provision, issue Sessions, mutate claims or cache positive authority.
type LoginSubjectResolver interface {
	ResolveLoginSubject(context.Context, SubjectLookup) (LoginSubjectSnapshot, error)
}

// SubjectResolutionOutcome is a closed private-operator result category.
type SubjectResolutionOutcome uint8

const (
	// SubjectResolutionUnknown is invalid and never indicates a grant.
	SubjectResolutionUnknown SubjectResolutionOutcome = iota
	// SubjectResolutionResolved reports a completed read, not final authority.
	SubjectResolutionResolved
	// SubjectResolutionRejected reports generic no-access or invalid evidence.
	SubjectResolutionRejected
	// SubjectResolutionUnavailable reports a failed dependency/read completion.
	SubjectResolutionUnavailable
	// SubjectResolutionLimited reports non-queuing concurrency rejection.
	SubjectResolutionLimited
)

// SubjectResolutionObserver accepts only bounded categories/duration, never data.
type SubjectResolutionObserver interface {
	SubjectResolutionOpened()
	SubjectResolutionClosed(SubjectResolutionOutcome, time.Duration)
}

// SubjectResolutionOptions bounds complete request work and concurrent admission.
type SubjectResolutionOptions struct {
	RequestTimeout time.Duration
	MaxConcurrent  int
}

// SubjectResolutionDependencies names resident crypto, one typed read and a clock.
type SubjectResolutionDependencies struct {
	Subjects LoginSubjectResolver
	Keys     *SubjectKeyring
	Clock    StartClock
	Observer SubjectResolutionObserver
}

// SubjectResolutionService owns bounded existing-subject resolution, no write unit.
type SubjectResolutionService struct {
	options      SubjectResolutionOptions
	dependencies SubjectResolutionDependencies
	active       chan struct{}
}

// NewSubjectResolutionService rejects incomplete security/budget dependencies.
func NewSubjectResolutionService(
	options SubjectResolutionOptions,
	dependencies SubjectResolutionDependencies,
) (*SubjectResolutionService, error) {
	validBudget := options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second
	validConcurrency := options.MaxConcurrent > 0 && options.MaxConcurrent <= 256
	validDependencies := dependencies.Subjects != nil && dependencies.Clock != nil && dependencies.Observer != nil
	if !validBudget || !validConcurrency || !validDependencies || !dependencies.Keys.isValid() {
		return nil, ErrInvalidSubjectResolution
	}
	return &SubjectResolutionService{options: options, dependencies: dependencies, active: make(chan struct{}, options.MaxConcurrent)}, nil
}

// ResolveBrowser accepts only opaque validated exchange evidence. Compute HMACs
// before the read, then check exact result and fresh cancellation/deadlines after
// completion. Provider auth_time remains optional; this use case issues no Session.
func (service *SubjectResolutionService) ResolveBrowser(
	ctx context.Context,
	exchange ExchangeResult,
) (result LoginSubjectSnapshot, resultErr error) {
	if ctx == nil || service == nil || service.active == nil {
		return result, ErrInvalidSubjectResolution
	}
	startedAt := time.Now()
	service.dependencies.Observer.SubjectResolutionOpened()
	defer func() {
		service.dependencies.Observer.SubjectResolutionClosed(subjectResolutionOutcome(resultErr), time.Since(startedAt))
	}()
	ctx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	if !exchange.IsValid() || ctx.Err() != nil || !liveSubjectExchange(exchange, service.dependencies.Clock.Now()) {
		return result, errors.Join(ErrSubjectResolutionRejected, ctx.Err())
	}
	select {
	case service.active <- struct{}{}:
		defer func() { <-service.active }()
	default:
		return result, ErrSubjectResolutionLimited
	}
	digests, err := service.dependencies.Keys.Digests(exchange.claimed.snapshot.Route(), exchange.identity)
	if err != nil {
		return result, ErrSubjectResolutionRejected
	}
	query, err := NewSubjectLookup(exchange.claimed, digests)
	if err != nil {
		return result, ErrSubjectResolutionRejected
	}
	if ctx.Err() != nil || !liveSubjectExchange(exchange, service.dependencies.Clock.Now()) {
		return result, errors.Join(ErrSubjectResolutionRejected, ctx.Err())
	}
	snapshot, err := service.dependencies.Subjects.ResolveLoginSubject(ctx, query)
	if err != nil {
		// Cleanup failure dominates a preceding no-access result: no positive
		// evidence escapes, and operators retain dependency-failure telemetry.
		if errors.Is(err, ErrSubjectResolutionRejected) && !errors.Is(err, ErrSubjectResolutionUnavailable) {
			return result, errors.Join(ErrSubjectResolutionRejected, ctx.Err())
		}
		return result, errors.Join(ErrSubjectResolutionUnavailable, ctx.Err())
	}
	now := service.dependencies.Clock.Now()
	validCompletion := snapshot.Matches(query) && authorityTimeReached(now, snapshot.EvaluatedAt()) && liveSubjectExchange(exchange, now)
	validMembership := snapshot.MembershipExpiresAt().IsZero() || now.Before(snapshot.MembershipExpiresAt())
	if !validCompletion || !validMembership || ctx.Err() != nil {
		return result, errors.Join(ErrSubjectResolutionRejected, ctx.Err())
	}
	return snapshot, nil
}

func liveSubjectExchange(exchange ExchangeResult, now time.Time) bool {
	validIdentity := exchange.IsValid() && exchange.identity.Issuer() == exchange.claimed.snapshot.Route().Issuer()
	validDeadlines := liveClaimAtLocalClock(exchange.claimed, now) && now.Before(exchange.identity.ExpiresAt())
	return validIdentity && validDeadlines
}

func subjectResolutionOutcome(err error) SubjectResolutionOutcome {
	switch {
	case err == nil:
		return SubjectResolutionResolved
	case errors.Is(err, ErrSubjectResolutionLimited):
		return SubjectResolutionLimited
	case errors.Is(err, ErrSubjectResolutionUnavailable):
		return SubjectResolutionUnavailable
	default:
		return SubjectResolutionRejected
	}
}
