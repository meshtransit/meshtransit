package oidcauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidIssue rejects unsafe setup before effects.
	ErrInvalidIssue = errors.New("oidc auth: invalid session issuance")
	// ErrIssueRejected conceals expired, stale or nonqualifying authentication.
	ErrIssueRejected = errors.New("oidc auth: session issuance rejected")
	// ErrIssueUnavailable conceals write/evidence dependency details.
	ErrIssueUnavailable = errors.New("oidc auth: session issuance unavailable")
	// ErrIssueLimited rejects excess work without queueing.
	ErrIssueLimited = errors.New("oidc auth: session issuance limited")
	// ErrIssueCleanupFailed retains bounded joined rollback failure.
	ErrIssueCleanupFailed = errors.New("oidc auth: session issuance cleanup failed")
)

// IssueIDParams contains six distinct fresh public identities for two events.
type IssueIDParams struct {
	SessionID                                                                  accountsession.ID
	ChangeID, SessionAuditID, SessionOutboxID, SuccessAuditID, SuccessOutboxID publicid.ID
}

// IssueIDs is immutable identity evidence for one atomic two-aggregate mutation.
type IssueIDs struct{ params IssueIDParams }

// NewIssueIDs validates disjoint UUIDv7 identities, never internal sequences.
func NewIssueIDs(params IssueIDParams) (IssueIDs, error) {
	ids := IssueIDs{params: params}
	if !ids.IsValid() {
		return IssueIDs{}, ErrInvalidIssue
	}
	return ids, nil
}

func (ids IssueIDs) values() [6]publicid.ID {
	p := ids.params
	return [6]publicid.ID{publicid.ID(p.SessionID), p.ChangeID, p.SessionAuditID,
		p.SessionOutboxID, p.SuccessAuditID, p.SuccessOutboxID}
}

// IsValid rejects missing, duplicate or malformed evidence identities.
func (ids IssueIDs) IsValid() bool {
	values := ids.values()
	for index, id := range values {
		if !id.IsValid() {
			return false
		}
		for _, previous := range values[:index] {
			if id == previous {
				return false
			}
		}
	}
	return true
}

// SessionID returns the freshly allocated opaque Session public ID.
func (ids IssueIDs) SessionID() accountsession.ID { return ids.params.SessionID }

// ChangeID returns the one shared transaction evidence identity.
func (ids IssueIDs) ChangeID() publicid.ID { return ids.params.ChangeID }

// SessionAuditID returns Session-created audit identity.
func (ids IssueIDs) SessionAuditID() publicid.ID { return ids.params.SessionAuditID }

// SessionOutboxID returns Session-created outbox identity.
func (ids IssueIDs) SessionOutboxID() publicid.ID { return ids.params.SessionOutboxID }

// SuccessAuditID returns AuthTransaction-succeeded audit identity.
func (ids IssueIDs) SuccessAuditID() publicid.ID { return ids.params.SuccessAuditID }

// SuccessOutboxID returns AuthTransaction-succeeded outbox identity.
func (ids IssueIDs) SuccessOutboxID() publicid.ID { return ids.params.SuccessOutboxID }

// IssueMaterialGenerator prepares all randomness before Begin. It must not
// persist, replay or log a bearer and must respect the complete request budget.
type IssueMaterialGenerator interface {
	NewIssueMaterial(context.Context, deployment.ID, int64) (IssueIDs, accountsession.Token, error)
}

// SystemIssueMaterial uses bounded OS-CSPRNG token and UUIDv7 generation.
type SystemIssueMaterial struct{}

// NewIssueMaterial generates a fresh bearer and six disjoint identities.
func (SystemIssueMaterial) NewIssueMaterial(
	ctx context.Context, dep deployment.ID, epoch int64,
) (IssueIDs, accountsession.Token, error) {
	if ctx == nil || ctx.Err() != nil {
		return IssueIDs{}, accountsession.Token{}, ErrInvalidIssue
	}
	token, err := accountsession.GenerateToken(dep, epoch)
	if err != nil {
		return IssueIDs{}, accountsession.Token{}, ErrIssueUnavailable
	}
	var ids [6]publicid.ID
	for index := range ids {
		if ctx.Err() != nil {
			return IssueIDs{}, accountsession.Token{}, ErrIssueUnavailable
		}
		ids[index], err = publicid.New()
		if err != nil {
			return IssueIDs{}, accountsession.Token{}, ErrIssueUnavailable
		}
	}
	result, err := NewIssueIDs(IssueIDParams{SessionID: accountsession.ID(ids[0]),
		ChangeID: ids[1], SessionAuditID: ids[2], SessionOutboxID: ids[3], SuccessAuditID: ids[4], SuccessOutboxID: ids[5]})
	return result, token, err
}

// IssueOptions bounds the complete request, cleanup and Deployment lifetimes.
// Workspace membership may only shorten these configured whole-second ceilings.
type IssueOptions struct {
	RequestTimeout, RollbackTimeout, IdleLifetime, AbsoluteLifetime time.Duration
	MaxConcurrent                                                   int
}

func validIssueOptions(options IssueOptions) bool {
	validBudget := validClaimOptions(ClaimOptions{
		RequestTimeout: options.RequestTimeout, RollbackTimeout: options.RollbackTimeout,
	})
	validLifetimes := options.IdleLifetime > 0 && options.IdleLifetime <= options.AbsoluteLifetime &&
		options.AbsoluteLifetime <= 24*time.Hour && options.IdleLifetime%time.Second == 0 &&
		options.AbsoluteLifetime%time.Second == 0
	return validBudget && validLifetimes && options.MaxConcurrent > 0 && options.MaxConcurrent <= 256
}

// IssueCommand is prepared only by the application from opaque validated
// exchange, exact snapshot and resident crypto. It contains no raw bearer/SID.
type IssueCommand struct {
	lookup                         SubjectLookup
	subject                        LoginSubjectSnapshot
	authTime, providerExpiresAt    time.Time
	acr                            string
	amr                            []string
	hasSID                         bool
	ids                            IssueIDs
	tokenDigest                    accountsession.Digest
	sidDigest                      ProviderSessionDigest
	idleLifetime, absoluteLifetime time.Duration
}

// Lookup returns the original consuming binding and bounded HMAC candidates.
func (command IssueCommand) Lookup() SubjectLookup { return command.lookup }

// Subject returns optimistic evidence that must be locked and rechecked.
func (command IssueCommand) Subject() LoginSubjectSnapshot { return command.subject }

// IDs returns fresh public mutation/evidence identities.
func (command IssueCommand) IDs() IssueIDs { return command.ids }

// TokenDigest returns active-key-only durable verifier evidence.
func (command IssueCommand) TokenDigest() accountsession.Digest { return command.tokenDigest }

// ProviderSessionDigest returns optional SID HMAC; zero means all-NULL columns.
func (command IssueCommand) ProviderSessionDigest() ProviderSessionDigest { return command.sidDigest }

// AuthenticationTime returns signed validated provider evidence, never iat/Now.
func (command IssueCommand) AuthenticationTime() time.Time { return command.authTime }

// ACR returns opaque bounded assurance only to the trusted write boundary.
func (command IssueCommand) ACR() string { return command.acr }

// AMR returns a defensive copy of assurance evidence.
func (command IssueCommand) AMR() []string { return slices.Clone(command.amr) }

// ProviderExpiresAt returns the exclusive token-evidence decision deadline.
func (command IssueCommand) ProviderExpiresAt() time.Time { return command.providerExpiresAt }

// IdleLifetime returns the configured whole-second idle ceiling.
func (command IssueCommand) IdleLifetime() time.Duration { return command.idleLifetime }

// AbsoluteLifetime returns the configured whole-second absolute ceiling.
func (command IssueCommand) AbsoluteLifetime() time.Duration { return command.absoluteLifetime }

// IsValid checks prepared shape, not current authority or Commit confirmation.
func (command IssueCommand) IsValid() bool {
	validIdentity := !command.AuthenticationTime().IsZero() && command.AuthenticationTime().Unix() > 0 &&
		command.AuthenticationTime().Nanosecond() == 0 && !command.ProviderExpiresAt().IsZero() &&
		command.ProviderExpiresAt().Nanosecond() == 0
	validLifetime := command.idleLifetime > 0 && command.idleLifetime <= command.absoluteLifetime &&
		command.absoluteLifetime <= 24*time.Hour && command.idleLifetime%time.Second == 0 &&
		command.absoluteLifetime%time.Second == 0
	validEvidence := command.lookup.IsValid() && command.subject.Matches(command.lookup) &&
		command.ids.IsValid() && command.tokenDigest.IsValid()
	if !validIdentity || !validLifetime || !validEvidence {
		return false
	}
	for _, id := range command.ids.values() {
		if id == publicid.ID(command.lookup.Claimed().TransactionID()) {
			return false
		}
	}
	return command.hasSID == command.sidDigest.IsValid()
}

// SemanticHash binds all prepared fences/digests without exposing private input.
func (command IssueCommand) SemanticHash() [32]byte {
	if !command.IsValid() {
		return [32]byte{}
	}
	input := []byte("meshtransit/oidc-auth/session-issuance-command/v1\x00")
	binding := command.lookup.Snapshot().SemanticHash()
	input = append(input, binding[:]...)
	for _, id := range command.ids.values() {
		value := id.Bytes()
		input = append(input, value[:]...)
	}
	for _, id := range []publicid.ID{
		publicid.ID(command.subject.PrincipalID()), publicid.ID(command.subject.IdentitySubjectID()),
		publicid.ID(command.subject.MembershipID()),
	} {
		value := id.Bytes()
		input = append(input, value[:]...)
	}
	for _, value := range []int64{
		command.subject.SubjectVersion(), command.subject.AccountVersion(), command.subject.MembershipVersion(),
		command.subject.PrincipalAuthorityGeneration(), command.subject.AccountSessionGeneration(),
		command.subject.MembershipAuthorityGeneration(),
		command.lookup.Claimed().ConsumedAt().UnixMicro(), command.subject.EvaluatedAt().UnixMicro(),
		command.AuthenticationTime().UnixMicro(), command.ProviderExpiresAt().UnixMicro(),
		int64(command.idleLifetime), int64(command.absoluteLifetime),
	} {
		input = binary.AppendVarint(input, value)
	}
	var membershipExpiry int64
	if !command.subject.MembershipExpiresAt().IsZero() {
		membershipExpiry = command.subject.MembershipExpiresAt().UnixMicro()
	}
	input = binary.AppendVarint(input, membershipExpiry)
	for _, digest := range command.lookup.Digests() {
		input = appendIssueField(input, digest.KeyID().String())
		value := digest.Bytes()
		input = append(input, value[:]...)
	}
	matched := command.subject.Digest().Bytes()
	input = append(input, matched[:]...)
	input = appendIssueField(input, command.subject.Digest().KeyID().String())
	input = appendIssueField(input, command.tokenDigest.KeyID().String())
	token := command.tokenDigest.Bytes()
	input = append(input, token[:]...)
	if command.sidDigest.IsValid() {
		input = appendIssueField(input, command.sidDigest.KeyID().String())
		sid := command.sidDigest.Bytes()
		input = append(input, sid[:]...)
	} else {
		input = appendIssueField(input, "")
	}
	input = appendIssueField(input, command.ACR())
	for _, method := range command.AMR() {
		input = appendIssueField(input, method)
	}
	return sha256.Sum256(input)
}
func appendIssueField(input []byte, value string) []byte {
	// All fields have already been validated <=2048 bytes before hashing.
	length := len(value)
	if length > 65535 {
		return nil
	}
	input = binary.BigEndian.AppendUint16(input, uint16(length))
	return append(input, value...)
}

// String redacts private write evidence.
func (IssueCommand) String() string { return "[REDACTED]" }

// GoString redacts detailed private write evidence.
func (IssueCommand) GoString() string { return "oidcauth.IssueCommand([REDACTED])" }

// LogValue redacts structured private write evidence.
func (IssueCommand) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Issued is validated atomic write metadata, not a bearer or confirmed Commit.
type Issued struct {
	command IssueCommand
	session accountsession.Session
	at      time.Time
}

// IssuedParams contains the exact metadata returned by the owned write boundary.
type IssuedParams struct {
	Command                                    IssueCommand
	SessionID                                  accountsession.ID
	Version                                    int64
	IssuedAt, IdleExpiresAt, AbsoluteExpiresAt time.Time
}

// NewIssued strictly validates durable identity/version and exact deadline intersection.
func NewIssued(params IssuedParams) (Issued, error) {
	command, id, version := params.Command, params.SessionID, params.Version
	at, idle, absolute := params.IssuedAt, params.IdleExpiresAt, params.AbsoluteExpiresAt
	at, idle, absolute = at.UTC(), idle.UTC(), absolute.UTC()
	validTime := canonicalSubjectTime(at) && canonicalSubjectTime(idle) && canonicalSubjectTime(absolute) &&
		!at.Before(command.subject.EvaluatedAt()) && !at.Before(command.AuthenticationTime()) &&
		liveClaim(command.lookup.Claimed(), at) && at.Before(command.ProviderExpiresAt())
	expectedIdle, expectedAbsolute := issueDeadlines(command, at)
	if !command.IsValid() || id != command.ids.SessionID() || version != 1 || !validTime ||
		!idle.Equal(expectedIdle) || !absolute.Equal(expectedAbsolute) || !at.Before(idle) {
		return Issued{}, ErrIssueRejected
	}
	route, subject := command.lookup.Snapshot().Route(), command.subject
	session, err := accountsession.NewSession(accountsession.Params{
		ID: id, DeploymentID: route.DeploymentID(), PrincipalID: subject.PrincipalID(),
		IdentitySubjectID: subject.IdentitySubjectID(), LoginWorkspaceID: route.WorkspaceID(), HasLoginWorkspace: true,
		AuthenticationTime: command.AuthenticationTime(), ACR: command.ACR(), AMR: command.AMR(), Version: version,
		PrincipalAuthorityGeneration: subject.PrincipalAuthorityGeneration(),
		AccountSessionGeneration:     subject.AccountSessionGeneration(),
		ProviderGeneration:           route.ProviderGeneration(), DeploymentRecoveryEpoch: route.RecoveryEpoch(),
		IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
	})
	if err != nil {
		return Issued{}, ErrIssueRejected
	}
	return Issued{command: command, session: session, at: at}, nil
}
func issueDeadlines(command IssueCommand, at time.Time) (time.Time, time.Time) {
	idle, absolute := at.Add(command.idleLifetime), at.Add(command.absoluteLifetime)
	if expiry := command.subject.MembershipExpiresAt(); !expiry.IsZero() {
		if expiry.Before(idle) {
			idle = expiry
		}
		if expiry.Before(absolute) {
			absolute = expiry
		}
	}
	return idle, absolute
}

// IsValid checks immutable write metadata; it does not claim confirmed Commit.
func (issued Issued) IsValid() bool {
	if !issued.command.IsValid() || !issued.session.IsValid() || !canonicalSubjectTime(issued.at) {
		return false
	}
	expected, err := NewIssued(IssuedParams{
		Command: issued.command, SessionID: issued.session.ID(), Version: issued.session.Version(),
		IssuedAt: issued.at, IdleExpiresAt: issued.session.IdleExpiresAt(),
		AbsoluteExpiresAt: issued.session.AbsoluteExpiresAt(),
	})
	if err != nil {
		return false
	}
	actual, want := issued.session, expected.session
	workspaceID, hasWorkspace := actual.LoginWorkspaceID()
	wantWorkspaceID, wantHasWorkspace := want.LoginWorkspaceID()
	return actual.DeploymentID() == want.DeploymentID() && actual.PrincipalID() == want.PrincipalID() &&
		actual.IdentitySubjectID() == want.IdentitySubjectID() && workspaceID == wantWorkspaceID &&
		hasWorkspace == wantHasWorkspace && actual.AuthenticationTime().Equal(want.AuthenticationTime()) &&
		actual.ACR() == want.ACR() && slices.Equal(actual.AMR(), want.AMR()) &&
		actual.PrincipalAuthorityGeneration() == want.PrincipalAuthorityGeneration() &&
		actual.AccountSessionGeneration() == want.AccountSessionGeneration() &&
		actual.ProviderGeneration() == want.ProviderGeneration() &&
		actual.DeploymentRecoveryEpoch() == want.DeploymentRecoveryEpoch()
}

// Matches rejects substituted prepared evidence from a trusted write port.
func (issued Issued) Matches(command IssueCommand) bool {
	expected, actual := command.SemanticHash(), issued.command.SemanticHash()
	return issued.IsValid() && command.IsValid() && hmac.Equal(actual[:], expected[:])
}

// Session returns metadata, never the raw token.
func (issued Issued) Session() accountsession.Session { return issued.session }

// IssuedAt returns live DB decision time after all lock waits.
func (issued Issued) IssuedAt() time.Time { return issued.at }

// SessionSemanticHash binds exact prepared authority and returned deadlines.
func (issued Issued) SessionSemanticHash() [32]byte {
	if !issued.IsValid() {
		return [32]byte{}
	}
	input := []byte("meshtransit/oidc-auth/issued-session/v1\x00")
	command := issued.command.SemanticHash()
	input = append(input, command[:]...)
	for _, at := range []time.Time{issued.at, issued.session.IdleExpiresAt(), issued.session.AbsoluteExpiresAt()} {
		input = binary.AppendVarint(input, at.UnixMicro())
	}
	return sha256.Sum256(input)
}

// SuccessSemanticHash binds original consumption to succeeded/version three and exact result.
func (issued Issued) SuccessSemanticHash() [32]byte {
	if !issued.IsValid() {
		return [32]byte{}
	}
	input := []byte("meshtransit/oidc-auth/browser-success-lifecycle/v1\x00")
	before := issued.command.lookup.Claimed().AfterSemanticHash()
	input = append(input, before[:]...)
	input = binary.BigEndian.AppendUint64(input, 3)
	input = binary.AppendVarint(input, issued.at.UnixMicro())
	id := publicid.ID(issued.session.ID()).Bytes()
	input = append(input, id[:]...)
	return sha256.Sum256(input)
}

// String redacts pre-Commit write evidence.
func (Issued) String() string { return "[REDACTED]" }

// GoString redacts detailed pre-Commit evidence.
func (Issued) GoString() string { return "oidcauth.Issued([REDACTED])" }

// LogValue redacts structured pre-Commit evidence.
func (Issued) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// IssueTransactions opens one owned short unit, never an uncertain-write resolver.
type IssueTransactions interface {
	BeginIssue(context.Context, Route) (IssueTransaction, error)
}

// IssueTransaction inserts Session, erases/terminalizes claim and appends two
// chained audit/outbox events atomically. Overlapping methods must reject.
type IssueTransaction interface {
	Issue(context.Context, IssueCommand) (Issued, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// IssueDependencies separates resident preparation from durable authority writes.
type IssueDependencies struct {
	Transactions     IssueTransactions
	Material         IssueMaterialGenerator
	Subjects         *SubjectKeyring
	Sessions         *accountsession.Keyring
	ProviderSessions ProviderSessionKey
	Clock            StartClock
	Observer         IssueObserver
}

// IssueService owns one bounded issuance attempt per opaque exchange.
type IssueService struct {
	options      IssueOptions
	dependencies IssueDependencies
	active       chan struct{}
}

// NewIssueService rejects incomplete security/budget configuration before effects.
func NewIssueService(options IssueOptions, dependencies IssueDependencies) (*IssueService, error) {
	validDependencies := dependencies.Transactions != nil && dependencies.Material != nil &&
		dependencies.Clock != nil && dependencies.Observer != nil &&
		dependencies.Subjects.isValid() && dependencies.Sessions.IsValid() && dependencies.ProviderSessions.key.isValid()
	if !validIssueOptions(options) || !validDependencies {
		return nil, ErrInvalidIssue
	}
	sid := dependencies.ProviderSessions.key.material
	if hmac.Equal(sid[:], dependencies.Subjects.active.key.material[:]) ||
		(dependencies.Subjects.hasPrevious && hmac.Equal(sid[:], dependencies.Subjects.previous.key.material[:])) {
		return nil, ErrInvalidIssue
	}
	return &IssueService{
		options: options, dependencies: dependencies, active: make(chan struct{}, options.MaxConcurrent),
	}, nil
}

// IssueBrowser prepares randomness/crypto before Begin, rechecks metadata before
// Commit and exposes a fresh Core bearer only after confirmed Commit/live release.
// Unknown completion never resolves, retries, refreshes or re-exchanges code.
func (service *IssueService) IssueBrowser(
	ctx context.Context, exchange ExchangeResult, subject LoginSubjectSnapshot,
) (result IssueResult, resultErr error) {
	if ctx == nil || service == nil || service.active == nil {
		return result, ErrInvalidIssue
	}
	startedAt := time.Now()
	service.dependencies.Observer.IssueOpened()
	defer func() {
		service.dependencies.Observer.IssueClosed(issueOutcome(resultErr), time.Since(startedAt))
	}()
	ctx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	now := service.dependencies.Clock.Now()
	expiry := subject.MembershipExpiresAt()
	liveMembership := expiry.IsZero() || now.Before(expiry)
	if !exchange.IsValid() || exchange.identity.AuthTime().IsZero() || exchange.identity.AuthTime().Unix() <= 0 ||
		!liveSubjectExchange(exchange, now) || !subject.IsValid() || !liveMembership ||
		!authorityTimeReached(now, subject.EvaluatedAt()) || ctx.Err() != nil {
		return result, errors.Join(ErrIssueRejected, ctx.Err())
	}
	digests, err := service.dependencies.Subjects.Digests(exchange.claimed.snapshot.Route(), exchange.identity)
	if err != nil {
		return result, ErrIssueRejected
	}
	lookup, err := NewSubjectLookup(exchange.claimed, digests)
	if err != nil || !subject.Matches(lookup) {
		return result, ErrIssueRejected
	}
	if !exchange.issuanceAttempt.CompareAndSwap(false, true) {
		return result, ErrIssueRejected
	}
	select {
	case service.active <- struct{}{}:
		defer func() { <-service.active }()
	default:
		return result, ErrIssueLimited
	}
	route := lookup.Snapshot().Route()
	ids, token, err := service.dependencies.Material.NewIssueMaterial(ctx, route.DeploymentID(), route.RecoveryEpoch())
	if err != nil || !token.IsValid() || token.DeploymentID() != route.DeploymentID() ||
		token.RecoveryEpoch() != route.RecoveryEpoch() {
		return result, errors.Join(ErrIssueUnavailable, ctx.Err())
	}
	digest, err := service.dependencies.Sessions.ActiveDigest(token)
	if err != nil {
		return result, ErrIssueUnavailable
	}
	sid, err := service.dependencies.ProviderSessions.session(route, exchange.identity)
	if err != nil {
		return result, ErrIssueRejected
	}
	command := IssueCommand{
		lookup: lookup, subject: subject, authTime: exchange.identity.AuthTime(),
		providerExpiresAt: exchange.identity.ExpiresAt(), acr: exchange.identity.ACR(), amr: exchange.identity.AMR(),
		hasSID: exchange.identity.SessionID() != "", ids: ids, tokenDigest: digest, sidDigest: sid,
		idleLifetime: service.options.IdleLifetime, absoluteLifetime: service.options.AbsoluteLifetime,
	}
	if !command.IsValid() || ctx.Err() != nil || !liveSubjectExchange(exchange, service.dependencies.Clock.Now()) {
		return result, errors.Join(ErrIssueRejected, ctx.Err())
	}
	unit, beginErr := service.dependencies.Transactions.BeginIssue(ctx, route)
	committed := false
	if unit != nil {
		defer func() {
			if committed {
				return
			}
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), service.options.RollbackTimeout)
			defer stop()
			if errors.Join(unit.Rollback(cleanup), cleanup.Err()) != nil {
				result, resultErr = IssueResult{}, errors.Join(resultErr, ErrIssueCleanupFailed)
			}
		}()
	}
	if beginErr != nil || unit == nil || ctx.Err() != nil {
		return result, errors.Join(ErrIssueUnavailable, ctx.Err())
	}
	issued, err := unit.Issue(ctx, command)
	if err != nil || !issued.Matches(command) {
		return result, errors.Join(ErrIssueUnavailable, ctx.Err())
	}
	if !liveIssuedRelease(exchange, issued, service.dependencies.Clock.Now()) || ctx.Err() != nil {
		return result, errors.Join(ErrIssueRejected, ctx.Err())
	}
	if err := unit.Commit(ctx); err != nil {
		if errors.Is(err, ErrCommitOutcomeUnknown) {
			return result, errors.Join(ErrIssueUnavailable, ErrCommitOutcomeUnknown, ctx.Err())
		}
		return result, errors.Join(ErrIssueUnavailable, ctx.Err())
	}
	committed = true
	if !liveIssuedRelease(exchange, issued, service.dependencies.Clock.Now()) || ctx.Err() != nil {
		return result, errors.Join(ErrIssueRejected, ctx.Err())
	}
	return IssueResult{issued: issued, token: token}, nil
}
func liveIssuedRelease(exchange ExchangeResult, issued Issued, now time.Time) bool {
	return issued.IsValid() && authorityTimeReached(now, issued.at) && liveSubjectExchange(exchange, now) &&
		issued.session.IsActiveAt(now)
}

// IssueResult is confirmed-only immutable Session evidence and fresh opaque bearer.
// Raw bearer release belongs only to a protected BFF Set-Cookie boundary.
type IssueResult struct {
	issued Issued
	token  accountsession.Token
}

// IsValid reports a released confirmed result, not a current RBAC grant.
func (result IssueResult) IsValid() bool {
	if !result.issued.IsValid() || !result.token.IsValid() {
		return false
	}
	route := result.issued.command.Lookup().Snapshot().Route()
	return result.token.DeploymentID() == route.DeploymentID() && result.token.RecoveryEpoch() == route.RecoveryEpoch()
}

// Session returns Core metadata; protected requests still recheck current authority/RBAC.
func (result IssueResult) Session() accountsession.Session { return result.issued.Session() }

// Token explicitly releases only the newly prepared confirmed Core bearer.
func (result IssueResult) Token() accountsession.Token { return result.token }

// String redacts bearer and identity evidence.
func (IssueResult) String() string { return "[REDACTED]" }

// GoString redacts detailed bearer and identity evidence.
func (IssueResult) GoString() string { return "oidcauth.IssueResult([REDACTED])" }

// LogValue redacts structured bearer and identity evidence.
func (IssueResult) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
