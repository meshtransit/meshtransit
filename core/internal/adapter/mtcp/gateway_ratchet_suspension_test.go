package mtcp

import (
	"context"
	"errors"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// suspendingGuard answers handshakes as schema 253 would for one gateway
// whose ratchet an approver may suspend.
type suspendingGuard struct {
	tokenGuard
	clock *testClock
	// until is the suspension's end, zero when none; read, when set, is
	// what a read during the session returns instead.
	until   time.Time
	read    *time.Time
	readErr error
	reads   int
}

func (guard *suspendingGuard) AcceptTimestampV4(ctx context.Context, fingerprint [32]byte, nodeKey []byte,
	timestampMS int64) (TimestampCheck, error) {
	check, err := guard.AcceptTimestampV3(ctx, fingerprint, nodeKey, timestampMS)
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.until.After(guard.clock.now()) {
		check.SuspendedUntil = guard.until
	}
	return check, err
}

func (guard *suspendingGuard) CommitGatewayTimestampV3(_ context.Context, _ [32]byte, _ []byte, _ int64,
	proven bool, mode kubecluster.GatewayTokenMode,
) (kubecluster.GatewayTimestampResult, bool, time.Time, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.proofs = append(guard.proofs, proven)
	if guard.result != "" {
		return guard.result, guard.ratcheted, time.Time{}, nil
	}
	suspended := guard.until.After(guard.clock.now())
	switch {
	case proven:
		guard.ratcheted, guard.until = true, time.Time{}
	case mode == kubecluster.GatewayTokenRatchet && guard.ratcheted && !suspended:
		return kubecluster.GatewayTimestampTokenRequired, true, time.Time{}, nil
	case mode == kubecluster.GatewayTokenRatchet && guard.ratcheted:
		return kubecluster.GatewayTimestampCommitted, true, guard.until, nil
	}
	return kubecluster.GatewayTimestampCommitted, guard.ratcheted, time.Time{}, nil
}

func (guard *suspendingGuard) ReadRatchetSuspension(context.Context, [32]byte, []byte) (time.Time, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.reads++
	if guard.readErr != nil {
		return time.Time{}, guard.readErr
	}
	if guard.read != nil {
		return *guard.read, nil
	}
	return guard.until, nil
}

func (guard *suspendingGuard) set(mutate func(*suspendingGuard)) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	mutate(guard)
}

func (guard *suspendingGuard) readCount() int {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.reads
}

// newSuspensionFixture is a ratcheted gateway suspended for suspended
// (none when zero), on a server using schema 253's functions.
func newSuspensionFixture(t *testing.T, mode kubecluster.GatewayTokenMode, suspended time.Duration) (tokenFixture,
	*suspendingGuard) {
	t.Helper()
	clock := &testClock{current: time.Now()}
	guard := &suspendingGuard{tokenGuard: tokenGuard{ratcheted: true}, clock: clock}
	if suspended > 0 {
		guard.until = clock.now().Add(suspended)
	}
	trust := &tokenTrust{trust: testRotationTrust()}
	f := newFixture(t, func(options *Options) {
		options.Now = clock.now
		options.Capabilities = append(options.Capabilities, CapabilityGatewayToken)
		options.GatewayTokens = &GatewayTokens{Guard: guard, Trust: trust, Mode: mode, Suspensions: guard}
	})
	return tokenFixture{fixture: f, guard: &guard.tokenGuard, trust: trust, clock: clock,
		gateway: newProvingNode(t, 0x62)}, guard
}

func TestGatewayRatchetSuspensionLetsASessionWithoutATokenThrough(t *testing.T) {
	f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, 10*time.Minute)
	start := f.clock.now()
	c := f.open(t, "", false)
	c.ping()
	if commits := guard.commits(); len(commits) != 1 || commits[0] {
		t.Fatalf("commits %v, want one without a token", commits)
	}
	// Read again every 30 s, the deadline holds until the suspension ends.
	f.clock.set(start.Add(5 * time.Minute))
	c.ping()
	if guard.readCount() == 0 {
		t.Fatal("the suspension was not read again")
	}
	f.clock.set(start.Add(10*time.Minute + time.Second))
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
}

func TestGatewayRatchetSuspensionResumedEndsTheSession(t *testing.T) {
	f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, time.Hour)
	start := f.clock.now()
	c := f.open(t, "", false)
	c.ping()
	guard.set(func(guard *suspendingGuard) { guard.until = time.Time{} })
	f.clock.set(start.Add(gatewaySuspensionReread + time.Second))
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
}

func TestGatewayRatchetSuspensionNeverExtendedByARead(t *testing.T) {
	t.Run("a later end read", func(t *testing.T) {
		f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, 5*time.Minute)
		start := f.clock.now()
		c := f.open(t, "", false)
		later := start.Add(time.Hour)
		guard.set(func(guard *suspendingGuard) { guard.read = &later })
		f.clock.set(start.Add(time.Minute))
		c.ping()
		f.clock.set(start.Add(5*time.Minute + time.Second))
		c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
		c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
	})
	t.Run("an unread suspension keeps its deadline", func(t *testing.T) {
		f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, 5*time.Minute)
		start := f.clock.now()
		c := f.open(t, "", false)
		guard.set(func(guard *suspendingGuard) { guard.readErr = errors.New("database down") })
		f.clock.set(start.Add(4 * time.Minute))
		c.ping()
		f.clock.set(start.Add(5*time.Minute + time.Second))
		c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
		c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
	})
}

func TestGatewayRatchetHeldWithoutASuspension(t *testing.T) {
	f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, 0)
	c := f.open(t, "", false)
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
	if commits := guard.commits(); len(commits) != 0 {
		t.Fatalf("a held ratchet reached the commit: %v", commits)
	}
}

func TestGatewayRatchetResumedBeforeTheCommit(t *testing.T) {
	// The handshake read a suspension a resume ended before the commit,
	// which decides under the Device's lock.
	f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, time.Hour)
	guard.result = kubecluster.GatewayTimestampTokenRequired
	c := f.open(t, "", false)
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
}

func TestGatewayRatchetSuspendedSessionWithATokenRunsOnIt(t *testing.T) {
	f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, 2*time.Minute)
	start := f.clock.now()
	c := f.open(t, f.podToken(t, "meshgw-0", start.Add(-time.Minute), 10*time.Minute), false)
	c.ping()
	if commits := guard.commits(); len(commits) != 1 || !commits[0] {
		t.Fatalf("commits %v, want one with a token", commits)
	}
	// The token, not the suspension, holds the session past its end.
	f.clock.set(start.Add(5 * time.Minute))
	c.ping()
	if guard.readCount() != 0 {
		t.Fatalf("a session on a token read the suspension %d times", guard.readCount())
	}
}

func TestGatewayRatchetSuspendedSessionThatJoinsWaitsForItsToken(t *testing.T) {
	session, _, _ := testSession(t)
	session.ctx, session.cancel = context.WithCancelCause(t.Context())
	clock := &testClock{current: time.Now()}
	guard := &suspendingGuard{clock: clock}
	session.server.options.Now = clock.now
	session.server.options.GatewayTokens = &GatewayTokens{Guard: guard, Trust: &tokenTrust{
		trust: testRotationTrust(),
	}, Mode: kubecluster.GatewayTokenRatchet, Suspensions: guard}
	session.capabilities = append(session.capabilities, CapabilityGatewayToken)
	start := clock.now()
	// A suspension of a minute, then the join clears it in the database.
	session.token.suspendedUntil, session.token.suspensionReadAt = start.Add(time.Minute), start
	nodeKey := node.Key(newProvingNode(t, 0x72).node.Public())
	if !session.ratchetJoinedGateway(t.Context(), nodeKey) {
		t.Fatal("the join did not ratchet")
	}
	joined := time.Unix(0, session.joinedAt.Load())
	if !session.gatewayTokenClock(joined.Add(gatewayJoinedTokenWait - time.Second)) {
		t.Fatal("the suspension's end cut a joined session before its token was due")
	}
	if session.gatewayTokenClock(joined.Add(gatewayJoinedTokenWait + time.Second)) {
		t.Fatal("a joined session with no token outlived its wait")
	}
	if guard.readCount() != 0 {
		t.Fatalf("a joined session read the suspension %d times", guard.readCount())
	}
}

// RatchetGatewayToken ratchets and, as schema 253's does, ends a suspension.
func (guard *suspendingGuard) RatchetGatewayToken(ctx context.Context, fingerprint [32]byte,
	nodeKey []byte) (bool, error) {
	ok, err := guard.tokenGuard.RatchetGatewayToken(ctx, fingerprint, nodeKey)
	guard.set(func(guard *suspendingGuard) { guard.until = time.Time{} })
	return ok, err
}

func TestGatewayRatchetSuspendedSessionRefresh(t *testing.T) {
	t.Run("a valid token ends the suspension", func(t *testing.T) {
		f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, 5*time.Minute)
		start := f.clock.now()
		c := f.open(t, "", false)
		c.ping()
		c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{
			PodToken: f.podToken(t, "meshgw-0", start.Add(-time.Minute), 10*time.Minute)})
		c.ping()
		guard.mu.Lock()
		ended, ratchets := guard.until.IsZero(), guard.ratchets
		guard.mu.Unlock()
		if !ended || ratchets != 1 {
			t.Fatalf("suspension ended %t, ratchets %d", ended, ratchets)
		}
		// The token, not the suspension's end, holds the session now.
		f.clock.set(start.Add(6 * time.Minute))
		c.ping()
	})
	t.Run("a bad token keeps the suspension's deadline", func(t *testing.T) {
		f, guard := newSuspensionFixture(t, kubecluster.GatewayTokenRatchet, 5*time.Minute)
		start := f.clock.now()
		c := f.open(t, "", false)
		c.ping()
		c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{
			PodToken: f.podToken(t, "meshgw-0", start.Add(-time.Hour), 10*time.Minute)})
		c.ping()
		guard.mu.Lock()
		ended := guard.until.IsZero()
		guard.mu.Unlock()
		if ended {
			t.Fatal("a bad token ended the suspension")
		}
		f.clock.set(start.Add(5*time.Minute + time.Second))
		c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
		c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
	})
}
