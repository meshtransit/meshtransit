package mtcpclient

import (
	"crypto/sha256"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// gatewayGroupsCapability is gateway.groups1: a gateway reports its groups'
// RBAC check (mtcp-v1 §6.11).
const gatewayGroupsCapability = "gateway.groups1"

const (
	// groupReportBeat is how often a gateway session looks at its groups:
	// Core writes one report per 30 s, so a little more (review d3c L3).
	groupReportBeat = 31 * time.Second
	// groupReportResend sends an unchanged report again, so Core sees the
	// gateway still checks (§6.11: at least every 10 minutes).
	groupReportResend = 10 * time.Minute
)

// SetGroupReportSource has a gateway report its groups' RBAC check on every
// session that negotiates gateway.groups1: source is read every
// groupReportBeat; nil from it sends nothing. It is ignored on a client that
// is not a gateway's, and must be set before the first session.
func (c *Client) SetGroupReportSource(source func() *mtcpv1.GatewayGroupReport) {
	if c.gateway != nil {
		c.groupReport = source
	}
}

// sendGroupReport sends the gateway's report when it changed since the
// session last sent it, or groupReportResend after; it reports a send
// failure, which ends the session. A report that breaks §6.11 is not sent:
// Core would end the session.
func (run *sessionRun) sendGroupReport(now time.Time) error {
	s := run.s
	source := run.stream.client.groupReport
	if !s.groups || source == nil {
		return nil
	}
	report := source()
	if report == nil || sharedmtcp.ValidateGatewayGroupReport(report) != nil {
		return nil
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(encoded)
	if digest == s.groupsDigest && now.Sub(s.groupsSent) < groupReportResend {
		return nil
	}
	if err := s.send(sharedmtcp.MessageGatewayGroupReport, report); err != nil {
		return err
	}
	s.groupsDigest, s.groupsSent = digest, now
	return nil
}
