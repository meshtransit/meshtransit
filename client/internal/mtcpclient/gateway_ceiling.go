package mtcpclient

import (
	"crypto/sha256"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// gatewayCeilingCapability is gateway.ceiling1: a gateway reports what each
// group's own RBAC lets it do (mtcp-v1 §6.12).
const gatewayCeilingCapability = "gateway.ceiling1"

const (
	// ceilingBeat is how often a gateway session looks at its ceiling.
	ceilingBeat = 61 * time.Second
	// ceilingSpacing: Core writes one ceiling per minute and Device.
	ceilingSpacing = 60 * time.Second
	// ceilingResend sends an unchanged ceiling again (§6.12: at least every
	// 6 hours), so Core sees it is still measured.
	ceilingResend = 6 * time.Hour
)

// SetGroupCeilingSource has a gateway report its groups' ceiling on every
// session that negotiates gateway.ceiling1: source is read every
// ceilingBeat; nil from it sends nothing. It is ignored on a client that is
// not a gateway's, and must be set before the first session.
func (c *Client) SetGroupCeilingSource(source func() *mtcpv1.GatewayGroupCeiling) {
	if c.gateway != nil {
		c.groupCeiling = source
	}
}

// sendGroupCeiling sends the gateway's ceiling when its content (all but
// checked_at_ms) changed and a minute passed since the session last sent
// one, or ceilingResend after; it reports a send failure, which ends the
// session. A ceiling that breaks §6.12 is not sent: Core would end the
// session.
func (run *sessionRun) sendGroupCeiling(now time.Time) error {
	s := run.s
	source := run.stream.client.groupCeiling
	if !s.ceiling || source == nil {
		return nil
	}
	ceiling := source()
	// One Core would refuse, or too large to encode, is not sent: sending
	// it would end this session, and the next would send it again (review
	// h4b M2).
	if ceiling == nil || sharedmtcp.ValidateGatewayGroupCeiling(ceiling) != nil ||
		proto.Size(ceiling) > sharedmtcp.MessageGatewayGroupCeiling.Limit() {
		return nil //nolint:nilerr // the session goes on
	}
	content := proto.CloneOf(ceiling)
	content.CheckedAtMs = 0
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(content)
	if err != nil {
		return nil //nolint:nilerr // nothing to send; the session goes on
	}
	digest := sha256.Sum256(encoded)
	since := now.Sub(s.ceilingSent)
	if !s.ceilingSent.IsZero() && (since < ceilingSpacing || digest == s.ceilingDigest && since < ceilingResend) {
		return nil
	}
	if err := s.send(sharedmtcp.MessageGatewayGroupCeiling, ceiling); err != nil {
		return err
	}
	s.ceilingDigest, s.ceilingSent = digest, now
	return nil
}
