package mtcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// tokenGuard answers handshakes as schema 246 would for one gateway.
type tokenGuard struct {
	mu        sync.Mutex
	ratcheted bool
	// result, when set, is the commit's answer instead of committed.
	result   kubecluster.GatewayTimestampResult
	proofs   []bool
	ratchets int
}

func (guard *tokenGuard) AcceptTimestampV3(context.Context, [32]byte, []byte, int64) (TimestampCheck, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	check := currentGateway
	check.TokenRatcheted = guard.ratcheted
	return check, nil
}

func (guard *tokenGuard) CommitGatewayTimestampV2(_ context.Context, _ [32]byte, _ []byte, _ int64, proven bool,
	_ kubecluster.GatewayTokenMode,
) (kubecluster.GatewayTimestampResult, bool, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.proofs = append(guard.proofs, proven)
	if guard.result != "" {
		return guard.result, guard.ratcheted, nil
	}
	guard.ratcheted = guard.ratcheted || proven
	return kubecluster.GatewayTimestampCommitted, guard.ratcheted, nil
}

func (guard *tokenGuard) RatchetGatewayToken(context.Context, [32]byte, []byte) (bool, error) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.ratchets++
	guard.ratcheted = true
	return true, nil
}

func (guard *tokenGuard) commits() []bool {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return append([]bool(nil), guard.proofs...)
}

// tokenTrust is the cluster trust the gateway's tokens check against.
type tokenTrust struct {
	mu    sync.Mutex
	trust kubecluster.RotationTrust
	err   error
	reads int
}

func (trust *tokenTrust) ReadRotationTrust(context.Context, node.MachineKey, node.Key) (kubecluster.RotationTrust,
	error) {
	trust.mu.Lock()
	defer trust.mu.Unlock()
	trust.reads++
	return trust.trust, trust.err
}

func (trust *tokenTrust) readCount() int {
	trust.mu.Lock()
	defer trust.mu.Unlock()
	return trust.reads
}

type tokenFixture struct {
	*fixture
	guard   *tokenGuard
	trust   *tokenTrust
	clock   *testClock
	gateway provingNode
}

func newTokenFixture(t *testing.T, mode kubecluster.GatewayTokenMode, ratcheted bool) tokenFixture {
	t.Helper()
	clock := &testClock{current: time.Now()}
	guard := &tokenGuard{ratcheted: ratcheted}
	trust := &tokenTrust{trust: testRotationTrust()}
	f := newFixture(t, func(options *Options) {
		options.Now = clock.now
		options.Capabilities = append(options.Capabilities, CapabilityGatewayToken)
		options.GatewayTokens = &GatewayTokens{Guard: guard, Trust: trust, Mode: mode}
	})
	return tokenFixture{fixture: f, guard: guard, trust: trust, clock: clock, gateway: newProvingNode(t, 0x61)}
}

// podToken is a token of pod at the fixture's clock, living lifetime.
func (f tokenFixture) podToken(t *testing.T, pod string, issuedAt time.Time, lifetime time.Duration) string {
	t.Helper()
	claims := testPodClaims(issuedAt, pod)
	claims["iat"], claims["nbf"] = issuedAt.Unix(), issuedAt.Unix()
	claims["exp"] = issuedAt.Add(lifetime).Unix()
	return signPodToken(t, testPodSigner(), claims)
}

// open dials the gateway with gateway.token1 (unless legacy) and proves its
// node key with token.
func (f tokenFixture) open(t *testing.T, token string, legacy bool) *client {
	t.Helper()
	options := dialOptions{machine: f.gateway.machine, nodeKey: f.gateway.node.Public()}
	if !legacy {
		options.capabilities = []string{CapabilityGatewayToken}
	}
	c, _, _ := f.dial(options)
	proof, err := sharedmtcp.NodeKeySessionProof(f.gateway.node, f.control.Public(), c.session.HandshakeHash())
	if err != nil {
		t.Fatal(err)
	}
	c.send(sharedmtcp.MessageNodeKeyProof, &mtcpv1.NodeKeyProof{Proof: proof[:], PodToken: token})
	return c
}

// contested reports whether the server holds machine contested.
func contested(server *Server, machine key.MachinePublic) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	_, held := server.contested[machine]
	return held
}

func (c *client) ping() {
	c.t.Helper()
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expect(sharedmtcp.MessagePong)
}

func TestGatewayTokenAtTheHandshake(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      kubecluster.GatewayTokenMode
		ratcheted bool
		token     string // valid, bad, none
		legacy    bool   // no gateway.token1
		refused   string // empty: the session goes on
		proven    bool
	}{
		{name: "valid token ratchets", mode: kubecluster.GatewayTokenRatchet, token: "valid", proven: true},
		{name: "no token, not ratcheted", mode: kubecluster.GatewayTokenRatchet, token: "none"},
		{
			name: "no token, ratcheted", mode: kubecluster.GatewayTokenRatchet, ratcheted: true, token: "none",
			refused: sharedmtcp.GateTokenRequired,
		},
		{
			name: "token without gateway.token1, ratcheted", mode: kubecluster.GatewayTokenRatchet, ratcheted: true,
			token: "valid", legacy: true, refused: sharedmtcp.GateTokenRequired,
		},
		{name: "bad token, not ratcheted", mode: kubecluster.GatewayTokenRatchet, token: "bad"},
		{
			name: "bad token, ratcheted", mode: kubecluster.GatewayTokenRatchet, ratcheted: true, token: "bad",
			refused: sharedmtcp.GateTokenRefused,
		},
		{
			name: "token ahead of Core, ratcheted", mode: kubecluster.GatewayTokenRatchet, ratcheted: true,
			token: "ahead", refused: sharedmtcp.GateTokenClockSkew,
		},
		{
			name: "no token, required", mode: kubecluster.GatewayTokenRequired, token: "none",
			refused: sharedmtcp.GateTokenRequired,
		},
		{name: "no token, ratcheted, observe", mode: kubecluster.GatewayTokenObserve, ratcheted: true, token: "none"},
		{name: "bad token, ratcheted, observe", mode: kubecluster.GatewayTokenObserve, ratcheted: true, token: "bad"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newTokenFixture(t, test.mode, test.ratcheted)
			now := f.clock.now()
			token := ""
			switch test.token {
			case "valid":
				token = f.podToken(t, "meshgw-0", now.Add(-time.Minute), 10*time.Minute)
			case "bad":
				token = f.podToken(t, "meshgw-1", now.Add(-time.Minute), 10*time.Minute) // another pod
			case "ahead":
				token = f.podToken(t, "meshgw-0", now.Add(3*time.Minute), 10*time.Minute)
			}
			c := f.open(t, token, test.legacy)
			if test.refused != "" {
				c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, test.refused)
				if len(f.guard.commits()) != 0 || f.handler.opened.Load() != 0 {
					t.Fatalf("a refused session committed %v or opened", f.guard.commits())
				}
				// Refused for its token, never contested as a replay.
				if contested(f.server, f.gateway.machine.Public()) {
					t.Fatal("a session refused for its token contested the key")
				}
				return
			}
			c.ping()
			if commits := f.guard.commits(); len(commits) != 1 || commits[0] != test.proven {
				t.Fatalf("commits %v, want one proven=%t", commits, test.proven)
			}
		})
	}
}

// Another replica ratcheted the Device between the read and the commit:
// refused as a missing token, not a replay (review v2 N1).
func TestGatewayTokenRequiredAtTheCommitIsNotAReplay(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
	f.guard.result = kubecluster.GatewayTimestampTokenRequired
	c := f.open(t, "", false)
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRequired)
	if contested(f.server, f.gateway.machine.Public()) {
		t.Fatal("the ratchet race contested the key")
	}
}

func TestGatewayTokenRefreshAndClock(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
	start := f.clock.now()
	first := f.podToken(t, "meshgw-0", start.Add(-time.Minute), 10*time.Minute) // exp start+9m
	c := f.open(t, first, false)
	c.ping()
	reads := f.trust.readCount()
	// The same token again is not checked; a new one moves the deadline
	// without reading the trust.
	c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{PodToken: first})
	c.ping()
	f.clock.advance(8 * time.Minute)
	second := f.podToken(t, "meshgw-0", f.clock.now().Add(-10*time.Second), 10*time.Minute) // exp start+18m
	c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{PodToken: second})
	c.ping()
	if f.trust.readCount() != reads {
		t.Fatalf("a refresh read the trust: %d reads, want %d", f.trust.readCount(), reads)
	}
	// Past the first token's exp plus the tolerance, the second holds.
	f.clock.set(start.Add(9*time.Minute + gatewayTokenSkew + time.Minute))
	c.ping()
	// Past the second's: the session ends.
	f.clock.set(start.Add(18*time.Minute + gatewayTokenSkew + time.Second))
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenExpired)
}

func TestGatewayTokenRefreshRefusals(t *testing.T) {
	t.Run("another pod's token ends the session", func(t *testing.T) {
		f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
		now := f.clock.now()
		c := f.open(t, f.podToken(t, "meshgw-0", now.Add(-time.Minute), 10*time.Minute), false)
		c.ping()
		c.send(sharedmtcp.MessageGatewayPodToken,
			&mtcpv1.GatewayPodToken{PodToken: f.podToken(t, "meshgw-1", now, 10*time.Minute)})
		c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRefused)
	})
	t.Run("too many tokens", func(t *testing.T) {
		f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
		now := f.clock.now()
		c := f.open(t, f.podToken(t, "meshgw-0", now.Add(-time.Minute), 10*time.Minute), false)
		c.ping()
		for index := range 2 {
			c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{
				PodToken: f.podToken(t, "meshgw-0", now.Add(-time.Duration(index+2)*time.Second), 10*time.Minute),
			})
		}
		c.ping()
		c.send(sharedmtcp.MessageGatewayPodToken,
			&mtcpv1.GatewayPodToken{PodToken: f.podToken(t, "meshgw-0", now.Add(-5*time.Second), 10*time.Minute)})
		failure := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
		if failure.GetCode() != mtcpv1.Error_OVERLOADED || !failure.GetFatal() {
			t.Fatalf("error %+v, want fatal OVERLOADED", failure)
		}
	})
	t.Run("without gateway.token1", func(t *testing.T) {
		f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
		c := f.open(t, "", true)
		c.ping()
		c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{PodToken: "x"})
		failure := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
		if failure.GetCode() != mtcpv1.Error_INVALID || !failure.GetFatal() {
			t.Fatalf("error %+v, want fatal INVALID", failure)
		}
	})
	t.Run("the trust lacks the key and cannot be read: the deadline holds", func(t *testing.T) {
		f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
		now := f.clock.now()
		c := f.open(t, f.podToken(t, "meshgw-0", now.Add(-time.Minute), 10*time.Minute), false)
		c.ping()
		f.trust.mu.Lock()
		f.trust.err = errors.New("database down")
		f.trust.mu.Unlock()
		f.clock.advance(2 * time.Minute)
		rotated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// A token the cached trust cannot check (the cluster rotated its
		// key): read again, which fails; the session goes on.
		c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{
			PodToken: signPodToken(t, rotated, testPodClaims(f.clock.now(), "meshgw-0")),
		})
		c.ping()
		if f.trust.readCount() != 2 {
			t.Fatalf("trust reads %d, want the handshake's and one again", f.trust.readCount())
		}
	})
}

func TestGatewayTokenObserveNeverCuts(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenObserve, false)
	start := f.clock.now()
	c := f.open(t, f.podToken(t, "meshgw-0", start.Add(-time.Minute), 10*time.Minute), false)
	c.ping()
	f.clock.set(start.Add(time.Hour))
	c.ping()
}

func TestGatewayTokenOptionsMatchTheCapability(t *testing.T) {
	resolverOptions := func(mutate func(*Options)) error {
		options := Options{Keys: []ControlKey{{NotAfter: time.Now()}}}
		mutate(&options)
		_, err := NewServer(options)
		return err
	}
	tokens := &GatewayTokens{Guard: &tokenGuard{}, Trust: &tokenTrust{}, Mode: kubecluster.GatewayTokenRatchet}
	for name, mutate := range map[string]func(*Options){
		"tokens without the capability": func(options *Options) { options.GatewayTokens = tokens },
		"the capability without tokens": func(options *Options) {
			options.Capabilities = []string{CapabilityGatewayToken}
		},
		"an unknown mode": func(options *Options) {
			options.Capabilities = []string{CapabilityGatewayToken}
			options.GatewayTokens = &GatewayTokens{Guard: &tokenGuard{}, Trust: &tokenTrust{}, Mode: "off"}
		},
	} {
		if err := resolverOptions(mutate); !errors.Is(err, ErrInvalidServer) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A session with a pod token taking over one without is the pod moving to
// gateway.token1: not contested (review v2 N6). A second session with a
// token taking over one with a token still is.
func TestGatewayTokenSessionTakingOverALegacyOneIsNotContested(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
	now := f.clock.now()
	legacy := f.open(t, "", false)
	legacy.ping()
	upgraded := f.open(t, f.podToken(t, "meshgw-0", now.Add(-time.Minute), 10*time.Minute), false)
	upgraded.ping()
	if contested(f.server, f.gateway.machine.Public()) {
		t.Fatal("the pod's move to gateway.token1 contested its key")
	}
	again := f.open(t, f.podToken(t, "meshgw-0", now.Add(-50*time.Second), 10*time.Minute), false)
	again.ping()
	if !contested(f.server, f.gateway.machine.Public()) {
		t.Fatal("a second session with a token did not contest the key")
	}
}

// A legacy session's first valid token starts its deadline but never
// ratchets the Device (review v2 N5); past it the session ends.
func TestGatewayTokenOnALegacySessionStartsItsDeadline(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
	start := f.clock.now()
	c := f.open(t, "", false)
	c.ping()
	c.send(sharedmtcp.MessageGatewayPodToken,
		&mtcpv1.GatewayPodToken{PodToken: f.podToken(t, "meshgw-0", start.Add(-time.Minute), 10*time.Minute)})
	c.ping()
	if commits := f.guard.commits(); len(commits) != 1 || commits[0] || f.guard.ratcheted {
		t.Fatalf("commits %v ratcheted %t: a refresh ratcheted the Device", commits, f.guard.ratcheted)
	}
	f.clock.set(start.Add(9*time.Minute + gatewayTokenSkew + time.Second))
	c.send(sharedmtcp.MessagePing, &mtcpv1.Ping{})
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenExpired)
}

// Mode required ends a session on a refused refresh.
func TestGatewayTokenRefusedRefreshUnderRequired(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenRequired, false)
	now := f.clock.now()
	c := f.open(t, f.podToken(t, "meshgw-0", now.Add(-time.Minute), 10*time.Minute), false)
	c.ping()
	c.send(sharedmtcp.MessageGatewayPodToken,
		&mtcpv1.GatewayPodToken{PodToken: f.podToken(t, "meshgw-1", now, 10*time.Minute)})
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateTokenRefused)
}

// The cluster rotated its signing key and an administrator pasted the new
// one: the session reads the trust again, at most once a minute, and takes
// the token (review v2 N3).
func TestGatewayTokenRereadsTheTrustForANewKey(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, false)
	now := f.clock.now()
	c := f.open(t, f.podToken(t, "meshgw-0", now.Add(-time.Minute), 10*time.Minute), false)
	c.ping()
	rotated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newToken := func(at time.Time) string { return signPodToken(t, rotated, testPodClaims(at, "meshgw-0")) }
	// Within the minute of the handshake's read: not read again, and the
	// session holds its deadline.
	f.clock.advance(30 * time.Second)
	c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{PodToken: newToken(f.clock.now())})
	c.ping()
	if f.trust.readCount() != 1 {
		t.Fatalf("trust reads %d, want the handshake's only", f.trust.readCount())
	}
	// The administrator pasted the new key; past the minute it is read.
	f.trust.mu.Lock()
	f.trust.trust.JWKS = jwksOf(t, rotated)
	f.trust.mu.Unlock()
	f.clock.advance(time.Minute)
	f.clock.advance(15 * time.Second) // the refresh budget
	c.send(sharedmtcp.MessageGatewayPodToken, &mtcpv1.GatewayPodToken{PodToken: newToken(f.clock.now())})
	c.ping()
	if f.trust.readCount() != 2 {
		t.Fatalf("trust reads %d, want one again", f.trust.readCount())
	}
	// The new token moved the deadline: the first token's exp has passed.
	f.clock.set(now.Add(9*time.Minute + gatewayTokenSkew + time.Second))
	c.ping()
}

// Core cannot read the trust at a ratcheted gateway's handshake: retry,
// never a refused token.
func TestGatewayTokenTrustUnavailableAtTheHandshake(t *testing.T) {
	f := newTokenFixture(t, kubecluster.GatewayTokenRatchet, true)
	f.trust.err = errors.New("database down")
	c := f.open(t, f.podToken(t, "meshgw-0", f.clock.now().Add(-time.Minute), 10*time.Minute), false)
	c.expectClosedWith(mtcpv1.Error_NOT_AUTHORIZED, sharedmtcp.GateUnavailable)
}

// jwksOf is a JWKS of key under kid k1, as signPodToken names it.
func jwksOf(t *testing.T, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	point, err := signer.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Appendf(nil, `{"keys":[{"use":"sig","kty":"EC","crv":"P-256","kid":"k1","alg":"ES256","x":%q,"y":%q}]}`,
		base64.RawURLEncoding.EncodeToString(point[1:33]), base64.RawURLEncoding.EncodeToString(point[33:65]))
}

// failingRatchet refuses to ratchet a joined gateway.
type failingRatchet struct{ tokenGuard }

func (*failingRatchet) RatchetGatewayToken(context.Context, [32]byte, []byte) (bool, error) {
	return false, errors.New("database down")
}

// The session that completed a cluster join with gateway.token1 ratchets
// its new Device and must send a valid token within 4 minutes (Q115, t2
// review M1); a ratchet that cannot be written ends it.
func TestGatewayTokenJoinedSession(t *testing.T) {
	joined := func(t *testing.T, guard GatewayTokenGuard) *Session {
		t.Helper()
		session, _, _ := testSession(t)
		session.ctx, session.cancel = context.WithCancelCause(t.Context())
		session.server.options.GatewayTokens = &GatewayTokens{Guard: guard, Trust: &tokenTrust{
			trust: testRotationTrust(),
		}, Mode: kubecluster.GatewayTokenRatchet}
		session.capabilities = append(session.capabilities, CapabilityGatewayToken)
		return session
	}
	nodeKey := node.Key(newProvingNode(t, 0x71).node.Public())

	guard := &tokenGuard{}
	session := joined(t, guard)
	if !session.ratchetJoinedGateway(t.Context(), nodeKey) || guard.ratchets != 1 || session.joinedAt.Load() == 0 {
		t.Fatalf("ratchet %d, joined at %d", guard.ratchets, session.joinedAt.Load())
	}
	if got, ok := session.tokenNodeKey(); !ok || got != nodeKey {
		t.Fatalf("the refresh would read the trust for %v", got)
	}
	start := time.Unix(0, session.joinedAt.Load())
	if !session.gatewayTokenClock(start.Add(3 * time.Minute)) {
		t.Fatal("a joined session was cut before its token was due")
	}
	if session.gatewayTokenClock(start.Add(gatewayJoinedTokenWait + time.Second)) {
		t.Fatal("a joined session with no token outlived its wait")
	}

	failed := joined(t, &failingRatchet{})
	if failed.ratchetJoinedGateway(t.Context(), nodeKey) || failed.joinedAt.Load() != 0 {
		t.Fatal("a join whose ratchet failed went on")
	}
}
