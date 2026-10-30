package mtcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/adapter/kubetoken"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/kubejoin"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// CapabilityGatewayToken is gateway.token1: a Kubernetes gateway presents
// its pod token in NodeKeyProof and refreshes it with GatewayPodToken
// (mtcp-v1 §6.7). Core offers it whenever its database has schema 246.
const CapabilityGatewayToken = "gateway.token1"

const (
	// gatewayTokenSkew is the tolerance each way of a session's token
	// times; the session ends at its last token's exp plus it (K1c-T Q109).
	gatewayTokenSkew = 120 * time.Second
	// gatewayTokenSkewWarning is the cluster clock offset Core warns about.
	gatewayTokenSkewWarning = 60 * time.Second
	// GatewayPodToken per session: 2 at once, then 1 per 15 s; the
	// handshake's proof does not count (mtcp-v1 §14).
	gatewayTokenRefreshBurst = 2
	gatewayTokenRefreshRate  = 1.0 / 15
	// gatewayTrustReread bounds how often a session reads its cluster's
	// trust again for a token the cached one refuses (review v2 N3).
	gatewayTrustReread = time.Minute
	// gatewayJoinedTokenWait is how long a joined session may run without
	// a valid GatewayPodToken: meshgw sends one at least every 2 minutes
	// (Q115, t2 review M1).
	gatewayJoinedTokenWait = 4 * time.Minute
)

// GatewayTokenGuard is schema 246's handshake functions in the server's
// terms: the timestamp read says whether the gateway is ratcheted, and the
// commit writes the ratchet with the timestamp, one Device at a time.
type GatewayTokenGuard interface {
	AcceptTimestampV3(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
		timestampMS int64) (TimestampCheck, error)
	CommitGatewayTimestampV2(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte, timestampMS int64,
		tokenProven bool, mode kubecluster.GatewayTokenMode) (result kubecluster.GatewayTimestampResult,
		ratcheted bool, err error)
	RatchetGatewayToken(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte) (bool, error)
}

// GatewayRatchetSuspensions is schema 253's handshake functions: an
// approver suspends a gateway's ratchet for at most a day (K1d d2b). Nil
// GatewayTokens.Suspensions keeps schema 246's, which ratchet regardless.
type GatewayRatchetSuspensions interface {
	AcceptTimestampV4(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte,
		timestampMS int64) (TimestampCheck, error)
	CommitGatewayTimestampV3(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte, timestampMS int64,
		tokenProven bool, mode kubecluster.GatewayTokenMode) (result kubecluster.GatewayTimestampResult,
		ratcheted bool, suspendedUntil time.Time, err error)
	ReadRatchetSuspension(ctx context.Context, machineFingerprint [32]byte, nodeKey []byte) (time.Time, error)
}

// gatewaySuspensionReread is how often a session let through by a
// suspended ratchet reads the suspension again, so a resume or a token
// proven elsewhere ends it (Q166).
const gatewaySuspensionReread = 30 * time.Second

// GatewayTrustReader reads what a gateway's pod token must match, for the
// keys its session proved (kubecluster.MachineKeyRotations has it).
type GatewayTrustReader interface {
	ReadRotationTrust(ctx context.Context, machineKey node.MachineKey, nodeKey node.Key) (
		kubecluster.RotationTrust, error)
}

// GatewayTokens turns gateway.token1 on (K1c-T). Every field is required.
type GatewayTokens struct {
	Guard GatewayTokenGuard
	Trust GatewayTrustReader
	Mode  kubecluster.GatewayTokenMode
	// Suspensions is optional: schema 253 granted at startup.
	Suspensions GatewayRatchetSuspensions
}

func (tokens *GatewayTokens) valid() bool {
	return tokens == nil || tokens.Guard != nil && tokens.Trust != nil && tokens.Mode.IsKnown()
}

// gatewayTokenState is a gateway session's pod token. The run loop alone
// touches it, except proven, which a later session of the key reads.
type gatewayTokenState struct {
	// proven: the handshake's token checked and the commit kept it.
	proven bool
	// ratcheted: the Device is ratcheted, as the handshake left it.
	ratcheted bool
	// until is the latest exp of a valid token; zero: no deadline yet.
	until time.Time
	last  [sha256.Size]byte
	trust kubecluster.RotationTrust
	// readAt is when trust was read; zero: never.
	readAt   time.Time
	refresh  rateBudget
	observed bool // an expiry observe mode let through was counted
	// suspendedUntil is the hard deadline of a session let through without
	// a token by a suspended ratchet (no skew added); zero otherwise.
	// suspensionReadAt is when it was last read.
	suspendedUntil   time.Time
	suspensionReadAt time.Time
}

// sessionTokenReason is the audit reason of a session refused for its
// token (schema 246, Q112).
func sessionTokenReason(reason kubetoken.Reason) kubecluster.KeyEventReason {
	switch reason {
	case kubetoken.ReasonMissing:
		return kubecluster.KeyEventSessionTokenMissing
	case kubetoken.ReasonUnknownKey:
		return kubecluster.KeyEventSessionTokenUnknownKey
	case kubetoken.ReasonSignature:
		return kubecluster.KeyEventSessionTokenSignature
	case kubetoken.ReasonExpired:
		return kubecluster.KeyEventSessionTokenExpired
	case kubetoken.ReasonAudience:
		return kubecluster.KeyEventSessionTokenAudience
	case kubetoken.ReasonIdentity:
		return kubecluster.KeyEventSessionTokenIdentity
	case kubetoken.ReasonClockSkew:
		return kubecluster.KeyEventSessionClockSkew
	default:
		return kubecluster.KeyEventSessionTokenMalformed
	}
}

// tokenRefusal is why a session's token was not accepted.
type tokenRefusal struct {
	reason kubecluster.KeyEventReason
	keyID  string
	// soft: the trust could not say (unread, or it lacks the token's key
	// and was read too recently to read again). It does not end a session
	// that holds a deadline: the clock does, if no token checks before.
	soft bool
}

func (refusal tokenRefusal) message() string {
	if refusal.reason == kubecluster.KeyEventSessionClockSkew {
		return sharedmtcp.GateTokenClockSkew
	}
	return sharedmtcp.GateTokenRefused
}

// readGatewayTrust reads the session's cluster trust for the keys it
// proved; the refusal is set when it cannot check a token.
func (session *Session) readGatewayTrust(ctx context.Context, nodeKey node.Key) (kubecluster.RotationTrust,
	*tokenRefusal,
) {
	readCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	trust, err := session.server.options.GatewayTokens.Trust.ReadRotationTrust(readCtx,
		node.MachineKey(session.machine), nodeKey)
	switch {
	case errors.Is(err, kubecluster.ErrNotFound), err == nil && !trust.Complete():
		// A gateway that joined before K1.1 has no trust: it joins again.
		return kubecluster.RotationTrust{}, &tokenRefusal{reason: kubecluster.KeyEventSessionTrustMissing, soft: true}
	case err != nil:
		return kubecluster.RotationTrust{}, &tokenRefusal{
			reason: kubecluster.KeyEventSessionTrustUnavailable,
			soft:   true,
		}
	}
	return trust, nil
}

// verifyGatewayToken checks raw against trust with a session's tolerance.
func (session *Session) verifyGatewayToken(raw string, trust kubecluster.RotationTrust) (kubetoken.Claims,
	*tokenRefusal,
) {
	jwks, err := kubejoin.ParseJWKS(trust.JWKS)
	if err != nil {
		return kubetoken.Claims{}, &tokenRefusal{reason: kubecluster.KeyEventSessionTrustUnavailable, soft: true}
	}
	now := session.server.options.Now()
	claims, err := kubetoken.Verify(raw, kubetoken.Expectation{
		Issuer: trust.Issuer, JWKS: jwks,
		Namespace: trust.Namespace, ServiceAccount: trust.ServiceAccount, PodName: trust.PodName,
		SessionSkew: gatewayTokenSkew,
	}, now)
	if refused, ok := errors.AsType[*kubetoken.RefusedError](err); ok {
		return kubetoken.Claims{}, &tokenRefusal{reason: sessionTokenReason(refused.Reason), keyID: refused.KeyID}
	}
	if err != nil {
		return kubetoken.Claims{}, &tokenRefusal{reason: kubecluster.KeyEventSessionTrustUnavailable, soft: true}
	}
	session.server.options.Metrics.gatewayTokenAccepted(now.Sub(claims.IssuedAt), claims.Expiry.Sub(now))
	if offset := now.Sub(claims.IssuedAt); offset < -gatewayTokenSkewWarning {
		session.server.options.Logger.Warn("mtcp gateway token issued ahead of Core's clock",
			"error_code", "kubernetes_cluster_clock_skew", "offset_seconds", int(offset.Seconds()))
	}
	return claims, nil
}

// reportTokenRefusal counts and audits a refused token, off the session's
// path (schema 246).
func (session *Session) reportTokenRefusal(refusal tokenRefusal) {
	session.server.options.Metrics.limited(gatewaySessionTokenLimit(refusal.reason))
	if refusal.reason == kubecluster.KeyEventSessionTrustUnavailable {
		return // Core's database, not the gateway: counted only (t2 review M2)
	}
	session.server.keyReports.reportToken(node.MachineKey(session.machine).Fingerprint(), refusal.reason,
		refusal.keyID)
}

// handshakeToken decides a gateway's handshake on its pod token (mtcp-v1
// §6.7), after the proof and before the replay check. It returns whether
// the token was proven, and the handshake result and refusal message when
// the session ends.
func (session *Session) handshakeToken(raw string, nodeKey node.Key) (proven bool, result, refused string) {
	tokens := session.server.options.GatewayTokens
	ratcheted := session.gate.TokenRatcheted
	// A suspended ratchet lets a session without a token through to the
	// commit, which decides again under the Device's lock (K1d d2b).
	suspended := tokens.Suspensions != nil && session.gate.SuspendedUntil.After(session.server.options.Now())
	enforce := tokens.Mode == kubecluster.GatewayTokenRequired ||
		tokens.Mode == kubecluster.GatewayTokenRatchet && ratcheted && !suspended
	// A token sent without gateway.token1 is ignored (mtcp-v1 §6.7).
	if !session.Supports(CapabilityGatewayToken) {
		raw = ""
	}
	if raw == "" {
		// A session a suspension lets in is not refused: the
		// gateway_token_suspended metric counts it (review d2b L3).
		if enforce || ratcheted && !suspended {
			session.reportTokenRefusal(tokenRefusal{reason: kubecluster.KeyEventSessionTokenMissing})
		}
		if enforce {
			return false, "gateway_token_required", sharedmtcp.GateTokenRequired
		}
		return false, "", ""
	}
	trust, refusal := session.readGatewayTrust(session.ctx, nodeKey)
	var claims kubetoken.Claims
	if refusal == nil {
		claims, refusal = session.verifyGatewayToken(raw, trust)
	}
	if refusal != nil {
		// Refused on a Device not yet ratcheted (mode ratchet), or in mode
		// observe: audited, and the session goes on without a token (N4).
		session.reportTokenRefusal(*refusal)
		switch {
		case !enforce:
			return false, "", ""
		case refusal.reason == kubecluster.KeyEventSessionTrustUnavailable:
			// Core could not read the trust: retry, never a verdict.
			return false, "internal", sharedmtcp.GateUnavailable
		}
		return false, "gateway_token_refused", refusal.message()
	}
	session.token.trust, session.token.readAt = trust, session.server.options.Now()
	session.token.until, session.token.last = claims.Expiry, sha256.Sum256([]byte(raw))
	return true, "", ""
}

// commitGatewayTokenTimestamp records a gateway's timestamp and ratchet
// (schema 246). It reports whether the session goes on, after refusing it
// otherwise.
func (session *Session) commitGatewayTokenTimestamp(nodeKey []byte, tokenProven bool,
	refuse func(result, message string) bool,
) bool {
	server := session.server
	ctx, cancel := context.WithTimeout(session.ctx, writeTimeout)
	defer cancel()
	timestamp := session.hello.GetTimestampMs()
	tokens := server.options.GatewayTokens
	fingerprint := node.MachineKey(session.machine).Fingerprint()
	var (
		result         kubecluster.GatewayTimestampResult
		ratcheted      bool
		suspendedUntil time.Time
		err            error
	)
	if tokens.Suspensions != nil {
		result, ratcheted, suspendedUntil, err = tokens.Suspensions.CommitGatewayTimestampV3(ctx, fingerprint,
			nodeKey, timestamp, tokenProven, tokens.Mode)
	} else {
		result, ratcheted, err = tokens.Guard.CommitGatewayTimestampV2(ctx, fingerprint, nodeKey, timestamp,
			tokenProven, tokens.Mode)
	}
	switch {
	case err != nil:
		server.options.Logger.WarnContext(ctx, "mtcp gateway timestamp failed",
			"error_code", "mtcp_timestamp_unavailable")
		return refuse("internal", sharedmtcp.GateUnavailable)
	case result == kubecluster.GatewayTimestampTokenRequired:
		// Another replica ratcheted the Device meanwhile: not a replay
		// (review v2 N1).
		session.reportTokenRefusal(tokenRefusal{reason: kubecluster.KeyEventSessionTokenMissing})
		return refuse("gateway_token_required", sharedmtcp.GateTokenRequired)
	case result != kubecluster.GatewayTimestampCommitted || !server.recent.accept(session.machine, timestamp):
		// The commit also fails when the keys stopped being current since
		// the gate (a rotation, a revocation): not a replay worth auditing.
		server.contest(session.machine)
		return refuse("replay", sharedmtcp.GateReplayed)
	}
	if !tokenProven {
		session.token = gatewayTokenState{refresh: session.token.refresh}
		switch {
		case !suspendedUntil.IsZero():
			// A suspended ratchet let it through: its end is a hard
			// deadline, read again while the session runs (Q166).
			session.token.suspendedUntil = suspendedUntil
			session.token.suspensionReadAt = server.options.Now()
			server.options.Metrics.limited(limitGatewayTokenSuspended)
		case session.gate.TokenRatcheted:
			// Mode observe let a session without a token through.
			server.options.Metrics.limited(limitGatewayTokenObserved)
		}
	}
	session.token.proven, session.token.ratcheted = tokenProven, ratcheted
	session.tokenProven.Store(tokenProven)
	return true
}

// refreshGatewayToken takes a GatewayPodToken (mtcp-v1 §6.7). It reports
// whether the session goes on.
func (session *Session) refreshGatewayToken(now time.Time, message *mtcpv1.GatewayPodToken) bool {
	tokens := session.server.options.GatewayTokens
	if tokens == nil || !session.Supports(CapabilityGatewayToken) || !session.servesGateway() {
		session.SendError(mtcpv1.Error_INVALID, "a pod token needs gateway.token1 on a gateway session", true)
		return false
	}
	if wait, ok := session.token.refresh.spend(now, 1); !ok {
		session.server.options.Metrics.limited(limitGatewayTokenRefresh)
		session.endOverloaded("too many pod tokens", wait)
		return false
	}
	raw := message.GetPodToken()
	digest := sha256.Sum256([]byte(raw))
	if digest == session.token.last && !session.token.until.IsZero() {
		return true // the same token: checked already
	}
	refusal := session.checkRefresh(now, raw)
	if refusal == nil {
		session.token.last = digest
		session.endSuspension()
		return true
	}
	session.reportTokenRefusal(*refusal)
	cut := tokens.Mode == kubecluster.GatewayTokenRequired || tokens.Mode == kubecluster.GatewayTokenRatchet &&
		(session.token.ratcheted || session.joinedAt.Load() != 0 || !session.token.until.IsZero())
	if refusal.soft && !session.token.until.IsZero() || refusal.reason == kubecluster.KeyEventSessionTrustUnavailable {
		// The deadline the session holds stands, and Core's own database
		// never ends a session; the clock does if no token checks.
		cut = false
	}
	if session.onSuspension() {
		// A suspended ratchet let the session in without a token: a bad
		// one (a stale projected volume) changes nothing, the suspension's
		// end still holds (review d2b M3).
		cut = false
	}
	if !cut {
		if tokens.Mode == kubecluster.GatewayTokenObserve {
			session.server.options.Metrics.limited(limitGatewayTokenObserved)
		}
		return true
	}
	session.SendError(mtcpv1.Error_NOT_AUTHORIZED, refusal.message(), true)
	return false
}

// checkRefresh checks a refreshed token against the session's cached trust,
// reading it again, at most once a minute, when the session has none or the
// cached one does not know the token's key (the cluster rotated its signing
// keys and an administrator pasted the new ones, review v2 N3).
func (session *Session) checkRefresh(now time.Time, raw string) *tokenRefusal {
	nodeKey, ok := session.tokenNodeKey()
	if !ok {
		return &tokenRefusal{reason: kubecluster.KeyEventSessionTrustMissing, soft: true}
	}
	reread := func() (bool, *tokenRefusal) {
		if !session.token.readAt.IsZero() && now.Sub(session.token.readAt) < gatewayTrustReread {
			return false, nil
		}
		session.token.readAt = now
		trust, refusal := session.readGatewayTrust(session.ctx, nodeKey)
		if refusal == nil {
			session.token.trust = trust
		}
		return true, refusal
	}
	if !session.token.trust.Complete() {
		if read, refusal := reread(); !read {
			return &tokenRefusal{reason: kubecluster.KeyEventSessionTrustUnavailable, soft: true}
		} else if refusal != nil {
			return refusal
		}
	}
	claims, refusal := session.verifyGatewayToken(raw, session.token.trust)
	if refusal != nil && unknownSigner(refusal.reason) {
		read, readRefusal := reread()
		switch {
		case readRefusal != nil:
			return readRefusal
		case read:
			claims, refusal = session.verifyGatewayToken(raw, session.token.trust)
		}
		if refusal != nil && unknownSigner(refusal.reason) {
			refusal.soft = true
		}
	}
	if refusal != nil {
		return refusal
	}
	// A legacy session's first token starts its deadline but never
	// ratchets the Device (review v2 N5).
	session.token.until = later(session.token.until, claims.Expiry)
	return nil
}

// unknownSigner reports a token whose key the cached trust may lack.
func unknownSigner(reason kubecluster.KeyEventReason) bool {
	return reason == kubecluster.KeyEventSessionTokenUnknownKey || reason == kubecluster.KeyEventSessionTokenSignature
}

// tokenNodeKey is the node key the session proved, at its handshake or in
// its cluster join, else its hello's.
func (session *Session) tokenNodeKey() (node.Key, bool) {
	if session.provenNodeKey.IsValid() {
		return session.provenNodeKey, true
	}
	if joined := session.joinedNodeKey.Load(); joined != nil {
		return *joined, true
	}
	hello := session.hello.GetNodeKey()
	if len(hello) != key.Size {
		return node.Key{}, false
	}
	return node.Key(hello), true
}

// gatewayTokenClock ends a session past its last token's exp plus the
// tolerance, or a joined session that sent no valid token in time (mtcp-v1
// §6.7). It reports whether the session goes on.
func (session *Session) gatewayTokenClock(now time.Time) bool {
	tokens := session.server.options.GatewayTokens
	if tokens == nil {
		return true
	}
	// A session that joined a cluster waits for its token as any other: the
	// join ratchets the Device and clears its suspension.
	if session.onSuspension() && session.joinedAt.Load() == 0 {
		return session.suspensionClock(now)
	}
	expired := !session.token.until.IsZero() && now.After(session.token.until.Add(gatewayTokenSkew))
	if joined := session.joinedAt.Load(); joined != 0 && session.token.until.IsZero() {
		expired = now.After(time.Unix(0, joined).Add(gatewayJoinedTokenWait))
	}
	if !expired {
		return true
	}
	if tokens.Mode == kubecluster.GatewayTokenObserve {
		if !session.token.observed {
			session.token.observed = true
			session.server.options.Metrics.limited(limitGatewayTokenObserved)
		}
		return true
	}
	session.reportTokenRefusal(tokenRefusal{reason: kubecluster.KeyEventSessionTokenExpired})
	session.SendError(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenExpired, true)
	return false
}

// onSuspension reports a session that a suspended ratchet let in and that
// has proven no token since.
func (session *Session) onSuspension() bool {
	return !session.token.suspendedUntil.IsZero() && session.token.until.IsZero()
}

// endSuspension ends the Device's suspension once a session that relied on
// it proves a token: the gateway is fixed, so the door closes now, as at a
// handshake (review d2b M2). The Device is ratcheted already, so this only
// clears the suspension. A failure keeps the session's mark, so the next
// valid refresh tries again.
func (session *Session) endSuspension() {
	if session.token.suspendedUntil.IsZero() || session.token.until.IsZero() {
		return
	}
	nodeKey, ok := session.tokenNodeKey()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(session.ctx, writeTimeout)
	defer cancel()
	bytes := nodeKey.Bytes()
	if _, err := session.server.options.GatewayTokens.Guard.RatchetGatewayToken(ctx,
		node.MachineKey(session.machine).Fingerprint(), bytes[:]); err != nil {
		session.server.options.Logger.WarnContext(ctx, "mtcp gateway ratchet suspension not ended",
			"error_code", "gateway_ratchet_suspension_unavailable")
		return
	}
	session.token.suspendedUntil = time.Time{}
}

// suspensionClock ends a session let through by a suspended ratchet when
// the suspension ends, is resumed or a token proven elsewhere ends it,
// reading it again every gatewaySuspensionReread. A read that fails keeps
// the deadline it holds: Core's own database never ends a session early,
// and never extends one (Q166).
func (session *Session) suspensionClock(now time.Time) bool {
	until := session.token.suspendedUntil
	if now.Sub(session.token.suspensionReadAt) >= gatewaySuspensionReread && now.Before(until) {
		session.token.suspensionReadAt = now
		if read, ok := session.readSuspension(); ok {
			// Never later than the deadline the session holds.
			if read.IsZero() || read.Before(until) {
				until = read
			}
		}
		session.token.suspendedUntil = until
	}
	if !until.IsZero() && now.Before(until) {
		return true
	}
	// Only mode ratchet hands out a deadline.
	session.server.options.Metrics.limited(limitGatewayTokenSuspensionEnded)
	session.reportTokenRefusal(tokenRefusal{reason: kubecluster.KeyEventSessionTokenMissing})
	session.SendError(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired, true)
	return false
}

// readSuspension reads the Device's suspension for the keys the session
// proved; false when it cannot be read.
func (session *Session) readSuspension() (time.Time, bool) {
	tokens := session.server.options.GatewayTokens
	nodeKey, ok := session.tokenNodeKey()
	if !ok || tokens.Suspensions == nil {
		return time.Time{}, false
	}
	ctx, cancel := context.WithTimeout(session.ctx, writeTimeout)
	defer cancel()
	bytes := nodeKey.Bytes()
	until, err := tokens.Suspensions.ReadRatchetSuspension(ctx, node.MachineKey(session.machine).Fingerprint(),
		bytes[:])
	if err != nil {
		session.server.options.Logger.WarnContext(ctx, "mtcp gateway ratchet suspension unread",
			"error_code", "gateway_ratchet_suspension_unavailable")
		return time.Time{}, false
	}
	return until, true
}

// ratchetJoinedGateway ratchets the Device a session's cluster join just
// created, when the session has gateway.token1: its join token was checked
// (review v1 M4). It reports whether the session goes on; when the ratchet
// cannot be written the session ends, and the gateway's next session
// ratchets it with its token (t1 review L5).
func (session *Session) ratchetJoinedGateway(ctx context.Context, nodeKey node.Key) bool {
	tokens := session.server.options.GatewayTokens
	if tokens == nil || !session.Supports(CapabilityGatewayToken) {
		return true
	}
	// Its own time: the join's context may be nearly spent (t2 review L1).
	ratchetCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	bytes := nodeKey.Bytes()
	ratcheted, err := tokens.Guard.RatchetGatewayToken(ratchetCtx, node.MachineKey(session.machine).Fingerprint(),
		bytes[:])
	if err != nil || !ratcheted {
		session.server.options.Logger.WarnContext(ctx, "mtcp joined gateway was not ratcheted",
			"error_code", "gateway_token_ratchet_failed")
		session.SendError(mtcpv1.Error_INTERNAL, sharedmtcp.GateUnavailable, true)
		return false
	}
	// Held by the run loop's refresh and clock: this runs elsewhere.
	session.joinedNodeKey.Store(&nodeKey)
	session.joinedAt.Store(session.server.options.Now().UnixNano())
	return true
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
