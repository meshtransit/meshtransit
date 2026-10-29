package mtcpclient

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/kubejoin"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	// gatewayCapability: Core takes NodeKeyProof as a session's first record
	// (mtcp-v1 §6.7); a Kubernetes gateway requires it.
	gatewayCapability = "session.proof1"
	// gatewayAheadLimit is how far ahead of Core a gateway's handshake may
	// run before it redials with the corrected clock; Core refuses 5 s.
	gatewayAheadLimit = 4 * time.Second
	// maxJoinWait bounds one wait for a cluster join's approval.
	maxJoinWait = 10 * time.Minute
)

// NewGateway returns a client for a Kubernetes gateway replica (mtcp-v1
// §6.6–6.8): its sessions declare session.proof1, open with a node key
// proof once the replica is a gateway, take their timestamps from Core's
// clock, and map the gateway gate's refusals to typed errors. meshd uses
// New, whose sessions are unchanged.
func NewGateway() *Client {
	client := New()
	client.gateway = newGatewayClock()
	return client
}

// gatewayClock keeps a gateway's handshake timestamps near Core's clock and
// strictly increasing per machine key, so the real pod is never refused as
// a replay of itself, nor as running ahead of Core.
type gatewayClock struct {
	mu     sync.Mutex
	offset time.Duration // Core's time minus the local time
	known  bool          // the offset came from a ServerHello
	// estimated: an offset was taken at all; candidate is a ServerHello's
	// offset far from it, taken when the next one agrees.
	estimated bool
	candidate *time.Duration
	last      map[key.MachinePublic]int64
}

func newGatewayClock() *gatewayClock {
	return &gatewayClock{last: make(map[key.MachinePublic]int64)}
}

// timestamp returns the next handshake timestamp for machine and the one
// before it, for withdraw.
func (clock *gatewayClock) timestamp(machine key.MachinePublic, now time.Time) (int64, int64) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	previous := clock.last[machine]
	next := max(previous+1, now.Add(clock.offset).UnixMilli())
	clock.last[machine] = next
	return next, previous
}

// withdraw takes back a timestamp Core never recorded: a gateway session
// closed before its proof, as Core records a gateway's timestamp only after
// it. Otherwise a timestamp sent ahead would hold every later one ahead.
func (clock *gatewayClock) withdraw(machine key.MachinePublic, sent, previous int64) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if clock.last[machine] == sent {
		clock.last[machine] = previous
	}
}

// maxClockOffset bounds what Core's time may differ from the local clock;
// beyond it the value is ignored as wrong.
const maxClockOffset = 10 * time.Minute

// observe takes Core's time from a ServerHello, or a key document's Date
// header (second resolution, over TLS) until a ServerHello came. A Date
// sets any offset, so a pod whose clock is far off can still connect; a
// ServerHello that moves the estimate by more than maxClockOffset is
// ignored as wrong.
func (clock *gatewayClock) observe(core, local time.Time, precise bool) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	offset := core.Sub(local)
	if core.UnixMilli() <= 0 || (!precise && clock.known) {
		return
	}
	if precise && clock.estimated && (offset-clock.offset > maxClockOffset || clock.offset-offset > maxClockOffset) {
		// A wrong value, or the local clock stepped: two ServerHellos that
		// agree are taken as the new truth.
		agrees := clock.candidate != nil && (offset-*clock.candidate).Abs() <= time.Second
		if !agrees {
			clock.candidate = &offset
			return
		}
	}
	clock.offset, clock.known, clock.estimated, clock.candidate = offset, precise, true, nil
}

// now is the time by Core's clock, as far as it is known.
func (clock *gatewayClock) now(local time.Time) time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return local.Add(clock.offset)
}

// coreNow is the time by Core's clock: a gateway's estimate, or the local
// clock for meshd.
func (c *Client) coreNow() time.Time {
	if c.gateway == nil {
		return c.now()
	}
	return c.gateway.now(c.now())
}

// CoreNow is the time by Core's clock as this client estimates it: what a
// gateway checks the deadlines of its peers' Kubernetes access against
// (mtcp-v1 §7.8); the local clock for meshd.
func (c *Client) CoreNow() time.Time { return c.coreNow() }

// gatewayError maps the gateway gate's refusals (mtcp-v1 §6.7, §6.8), or
// returns nil for any other Error.
func gatewayError(m *mtcpv1.Error) error {
	text := boundedText(m.GetMessage())
	switch {
	case m.GetCode() == mtcpv1.Error_SESSION_REPLACED:
		return fmt.Errorf("%w: %s", controlplane.ErrGatewayContested, text)
	case m.GetCode() != mtcpv1.Error_NOT_AUTHORIZED:
		return nil
	}
	switch m.GetMessage() {
	case sharedmtcp.GateMachineRetired:
		return controlplane.ErrMachineKeyRetired
	case sharedmtcp.GateNodeNotCurrent:
		return controlplane.ErrNodeKeyNotCurrent
	case sharedmtcp.GateMachineUnbound:
		return controlplane.ErrMachineKeyUnbound
	case sharedmtcp.GateReplayed:
		return controlplane.ErrGatewayContested
	case sharedmtcp.GateAhead:
		return controlplane.ErrGatewayClock
	case sharedmtcp.GateProveFirst:
		return controlplane.ErrGatewayProofRequired
	case sharedmtcp.GateUnavailable:
		// Core could not check the handshake: retry, never a verdict.
		return fmt.Errorf("%w: %s", controlplane.ErrRegistrationTemporary, text)
	case sharedmtcp.GateTokenClockSkew:
		return fmt.Errorf("%w: %s", controlplane.ErrGatewayClusterClockSkew, text)
	case sharedmtcp.GateTokenRequired, sharedmtcp.GateTokenRefused, sharedmtcp.GateTokenExpired:
		return fmt.Errorf("%w: %s", controlplane.ErrGatewayPodToken, text)
	}
	return nil
}

// sessionError classifies an Error from Core; a gateway's adds the gate's
// refusals and Core's wait.
func (c *Client) sessionError(m *mtcpv1.Error) error {
	if c.gateway == nil {
		return sessionError(m)
	}
	err := gatewayError(m)
	if err == nil {
		err = sessionError(m)
	}
	return controlplane.WithRetryAfter(err, time.Duration(m.GetRetryAfterMs())*time.Millisecond)
}

// gatewayProof is the node key a gateway's session proves, or none for
// meshd.
func (c *Client) gatewayProof(node key.NodePrivate) key.NodePrivate {
	if c.gateway == nil {
		return key.NodePrivate{}
	}
	return node
}

// gatewayReconnectDelay is how soon a gateway reconnects after another
// holder of its keys pushed it out: within 2 seconds, outside the backoff
// (mtcp-v1 §6.8).
func gatewayReconnectDelay() time.Duration {
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(time.Second)))
	if err != nil {
		return time.Second
	}
	return time.Second + time.Duration(random.Int64())
}

// gatewayReconnects reports an error a gateway answers by reconnecting at
// once.
func gatewayReconnects(err error) bool {
	return errors.Is(err, controlplane.ErrGatewayContested) || errors.Is(err, controlplane.ErrGatewayClock)
}

// ProbeGateway checks that a gateway's keys are its Device's current ones: a
// session that proves the node key and gets a Pong (mtcp-v1 §6.7).
func (c *Client) ProbeGateway(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	pinnedFingerprint string,
) error {
	s, err := c.openGatewaySession(ctx, controlURL, material, pinnedFingerprint)
	if err != nil {
		return err
	}
	defer s.close()
	return c.awaitPong(ctx, s)
}

// RotateMachineKey moves a gateway to next (mtcp-v1 §6.8). The caller
// staged next durably first, and never sends it again: Core does not
// repeat a rotation, so an unknown outcome is settled by probing.
func (c *Client) RotateMachineKey(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	pinnedFingerprint string, next key.MachinePrivate, podToken controlplane.PodToken,
) error {
	if next.IsZero() {
		return controlplane.ErrInvalidMaterial
	}
	s, err := c.openGatewaySession(ctx, controlURL, material, pinnedFingerprint)
	if err != nil {
		return err
	}
	defer s.close()
	if err := c.awaitPong(ctx, s); err != nil {
		return err
	}
	proof, err := sharedmtcp.MachineKeyRotationProof(next, s.control, s.noise.HandshakeHash())
	if err != nil {
		return controlplane.ErrInvalidMaterial
	}
	public := next.Public()
	if err := s.send(sharedmtcp.MessageRotateMachineKey, &mtcpv1.RotateMachineKey{
		NewMachineKey: public[:], Proof: proof[:], ServiceAccountToken: podToken.Reveal(),
	}); err != nil {
		return temporary(err)
	}
	deadline := time.Now().Add(answerTimeout)
	for {
		message, err := s.receiveUntil(ctx, deadline)
		if err != nil {
			return temporary(err)
		}
		switch m := message.(type) {
		case *mtcpv1.RotateMachineKeyResponse:
			return nil
		case *mtcpv1.Error:
			if m.GetCode() == mtcpv1.Error_NOT_PERMITTED && !m.GetFatal() {
				// Definitive: the key was used before, or the budget is
				// spent; the rotation surely did not commit.
				return controlplane.WithRetryAfter(fmt.Errorf("%w: %s", controlplane.ErrMachineKeyRotationRefused,
					boundedText(m.GetMessage())), time.Duration(m.GetRetryAfterMs())*time.Millisecond)
			}
			return c.sessionError(m)
		}
		// Map messages for the session are not needed.
	}
}

// openGatewaySession opens a session that proves the gateway's node key.
func (c *Client) openGatewaySession(ctx context.Context, controlURL string, material controlplane.KeyMaterial,
	pinnedFingerprint string,
) (*session, error) {
	if c.gateway == nil {
		return nil, fmt.Errorf("%w: not a gateway client", controlplane.ErrRegistration)
	}
	keys, err := c.openKeys(material)
	if err != nil {
		return nil, err
	}
	origin, err := c.origin(controlURL)
	if err != nil {
		return nil, err
	}
	if err := c.checkPinned(ctx, origin, keys.control, pinnedFingerprint); err != nil {
		return nil, err
	}
	nodePublic := keys.node.Public()
	return c.open(ctx, origin, sessionOptions{
		machine: keys.machine, control: keys.control, nodeKey: nodePublic[:], prove: keys.node,
	})
}

// awaitPong establishes the session with a Ping and waits for its Pong, or
// the gate's refusal.
func (c *Client) awaitPong(ctx context.Context, s *session) error {
	if err := s.send(sharedmtcp.MessagePing, &mtcpv1.Ping{}); err != nil {
		return temporary(err)
	}
	deadline := time.Now().Add(answerTimeout)
	for {
		message, err := s.receiveUntil(ctx, deadline)
		if err != nil {
			return temporary(err)
		}
		switch m := message.(type) {
		case *mtcpv1.Pong:
			return nil
		case *mtcpv1.Error:
			return c.sessionError(m)
		}
	}
}

// clusterJoinAuth is a cluster join's auth: what the pod reports, as
// canonical JSON (sorted keys).
func clusterJoinAuth(join *controlplane.ClusterJoin) (*mtcpv1.RegisterRequest_Auth, error) {
	if join.JoinKey == "" || len(join.Reported) > 16 {
		return nil, fmt.Errorf("%w: invalid cluster join", controlplane.ErrRegistration)
	}
	for field, value := range join.Reported {
		if field == "" || len(field) > 64 || len(value) > 256 {
			return nil, fmt.Errorf("%w: invalid cluster join report", controlplane.ErrRegistration)
		}
	}
	reported := []byte("{}")
	if len(join.Reported) > 0 {
		encoded, err := json.Marshal(join.Reported)
		if err != nil || len(encoded) > 2048 {
			return nil, fmt.Errorf("%w: invalid cluster join report", controlplane.ErrRegistration)
		}
		reported = encoded
	}
	return &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_ClusterJoin{
		ClusterJoin: &mtcpv1.RegisterRequest_ClusterJoin{
			JoinKey: join.JoinKey, Reported: reported,
			ServiceAccountToken: join.PodToken.Reveal(), ServiceAccountIssuer: join.Issuer,
			ServiceAccountJwks: join.JWKS,
		},
	}}, nil
}

// adminApprovalOutcome reads a cluster join's pending answer: the request
// ID ends up in the pod's log, so it must be a canonical UUID; the wait
// lasts at most Core's 10 minutes (with some clock slack).
func adminApprovalOutcome(pending *mtcpv1.RegisterResponse_Pending, now time.Time,
) (controlplane.RegistrationResult, error) {
	approval := pending.GetAdminApproval()
	clusterID, err := kubejoin.ParseClusterID(approval.GetClusterId())
	_, requestErr := kubejoin.ParseClusterID(approval.GetRequestId())
	expires := time.UnixMilli(pending.GetExpiresMs())
	if err != nil || requestErr != nil || pending.GetApprovalUrl() != "" || len(approval.GetRequestNonce()) != 32 ||
		!expires.After(now) || expires.After(now.Add(maxJoinWait+maxClockOffset)) {
		return controlplane.RegistrationResult{}, fmt.Errorf("%w: invalid admin approval", controlplane.ErrRegistration)
	}
	return controlplane.RegistrationResult{
		State: controlplane.RegistrationStateAdminApprovalRequired,
		Approval: &controlplane.AdminApproval{
			ClusterID: clusterID, RequestID: approval.GetRequestId(),
			RequestNonce: [32]byte(approval.GetRequestNonce()), ExpiresAt: expires,
		},
	}, nil
}

// conflictApproval reads the request a conflicting cluster join gets back:
// enough to print the replica's own code, with no wait.
func conflictApproval(approval *mtcpv1.RegisterResponse_AdminApproval) (*controlplane.AdminApproval, error) {
	clusterID, err := kubejoin.ParseClusterID(approval.GetClusterId())
	_, requestErr := kubejoin.ParseClusterID(approval.GetRequestId())
	if err != nil || requestErr != nil || len(approval.GetRequestNonce()) != 32 {
		return nil, fmt.Errorf("%w: invalid admin approval", controlplane.ErrRegistration)
	}
	return &controlplane.AdminApproval{
		ClusterID: clusterID, RequestID: approval.GetRequestId(),
		RequestNonce: [32]byte(approval.GetRequestNonce()),
	}, nil
}
