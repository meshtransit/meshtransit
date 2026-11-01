package mtcp

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/flowlog"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// CapabilityFlowReport is flow.report1: the node counts its traffic and
// sends connection logs with the token of FlowTicket (mtcp-v1 §9.1).
const CapabilityFlowReport = "flow.report1"

// ErrInvalidFlowSigner reports a signer built from incomplete keys.
var ErrInvalidFlowSigner = errors.New("mtcp: invalid connection log signer")

// FlowSigner signs nodes' connection log tokens (flowlog-v1 §3) with a key
// used for nothing else, for one receiver.
type FlowSigner struct {
	signer      flowlog.TokenSigner
	kid         string
	audience    string
	receiverKey []byte
	now         func() time.Time
}

// NewFlowSigner signs with signer, whose public key is public, for the
// receiver of deployment whose Noise static key is receiver. The public key
// names the signing key by kid.
func NewFlowSigner(signer flowlog.TokenSigner, public ed25519.PublicKey, deploymentID deployment.ID,
	receiver *ecdh.PublicKey, now func() time.Time,
) (*FlowSigner, error) {
	if signer == nil || receiver == nil || now == nil || !deploymentID.IsValid() ||
		len(public) != ed25519.PublicKeySize || len(receiver.Bytes()) != 32 {
		return nil, ErrInvalidFlowSigner
	}
	// The kid names public: a signer with another key would make every
	// token fail at the receiver.
	probe := []byte("meshtransit/flow-token/probe")
	if !ed25519.Verify(public, probe, signer.Sign(probe)) {
		return nil, ErrInvalidFlowSigner
	}
	return &FlowSigner{
		signer: signer, kid: flowlog.SigningKeyID(public), audience: "meshflow:" + deploymentID.String(),
		receiverKey: receiver.Bytes(), now: now,
	}, nil
}

// errNoFlowTicket reports a grant no token can be signed for now: the
// node's authority ends within the clock skew a receiver allows.
var errNoFlowTicket = errors.New("mtcp: no connection log ticket for this grant")

// ticket signs grant for the session's machine key: the token lives at most
// flowlog.MaxTokenLifetime and never past the node's authority.
func (signer *FlowSigner) ticket(grant mapsession.FlowGrant, machine [32]byte) (*mtcpv1.FlowTicket, time.Time,
	error,
) {
	issued := signer.now().UTC().Truncate(time.Millisecond)
	expires := issued.Add(flowlog.MaxTokenLifetime)
	deadline := grant.Deadline
	if deadline.IsZero() {
		deadline = grant.NotAfter
	}
	if !deadline.IsZero() && deadline.Before(expires) {
		expires = deadline.UTC().Truncate(time.Millisecond)
	}
	if !expires.After(issued.Add(flowlog.ClockSkew)) {
		return nil, time.Time{}, errNoFlowTicket
	}
	tokenID := make([]byte, 16)
	if _, err := rand.Read(tokenID); err != nil {
		return nil, time.Time{}, err
	}
	workspace, network, device := grant.Scope.WorkspaceID().Bytes(), grant.Scope.NetworkID().Bytes(),
		publicid.ID(grant.Device).Bytes()
	claims := &flowlogv1.FlowTokenClaims{
		Version: 1, Kid: signer.kid, Audience: signer.audience,
		WorkspaceId: workspace[:], NetworkId: network[:], DeviceId: device[:], MachineKey: machine[:],
		IssuedAtMs: issued.UnixMilli(), NotBeforeMs: issued.UnixMilli(), ExpiresAtMs: expires.UnixMilli(),
		TokenId: tokenID, WindowS: uint32(grant.WindowSeconds), //nolint:gosec // 60 to 300, checked by SignTokenWith
	}
	for _, role := range grant.Roles {
		switch role {
		case mapsession.FlowRoleDevice:
			claims.Roles = append(claims.Roles, flowlogv1.FlowTokenClaims_DEVICE)
		case mapsession.FlowRoleRouter:
			claims.Roles = append(claims.Roles, flowlogv1.FlowTokenClaims_ROUTER)
		case mapsession.FlowRoleExit:
			claims.Roles = append(claims.Roles, flowlogv1.FlowTokenClaims_EXIT)
		}
	}
	for _, site := range grant.Sites {
		id := site.Bytes()
		claims.SiteIds = append(claims.SiteIds, id[:])
	}
	for _, pool := range grant.ExitPools {
		id := pool.Bytes()
		claims.ExitPoolIds = append(claims.ExitPoolIds, id[:])
	}
	token, err := flowlog.SignTokenWith(claims, signer.signer)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &mtcpv1.FlowTicket{Token: token, NotAfterMs: expires.UnixMilli(), ReceiverKey: signer.receiverKey},
		expires, nil
}

var _ mapsession.FlowTicketSink = (*mapSink)(nil)

// TakesFlowTickets implements mapsession.FlowTicketSink: a session that
// negotiated flow.report1 on a Core that signs. A Kubernetes gateway takes
// none yet: its token would need its cluster (connection logs design C36).
func (sink *mapSink) TakesFlowTickets() bool {
	return sink.flow != nil && sink.session.Supports(CapabilityFlowReport) && !sink.session.servesGateway()
}

// SendFlowTicket implements mapsession.FlowTicketSink, only for the machine
// key the session authenticated with (a grant for another, as after a
// rotation this session did not make, gets none).
func (sink *mapSink) SendFlowTicket(_ context.Context, grant mapsession.FlowGrant, on bool) (time.Time, error) {
	if !on {
		// Taking a token back needs no capability beyond having sent it.
		if !sink.flowSent.Load() && !sink.TakesFlowTickets() {
			return time.Time{}, mapsession.ErrNoFlowTickets
		}
		if err := sink.session.Send(sharedmtcp.MessageFlowTicket, &mtcpv1.FlowTicket{}); err != nil {
			return time.Time{}, err
		}
		sink.flowSent.Store(false)
		return time.Time{}, nil
	}
	if !sink.TakesFlowTickets() {
		return time.Time{}, mapsession.ErrNoFlowTickets
	}
	machine := sink.session.Machine()
	if grant.MachineKey.Bytes() != [32]byte(machine) {
		return time.Time{}, nil
	}
	ticket, expires, err := sink.flow.ticket(grant, machine)
	if err != nil {
		// Nothing a node sent causes this (an authority about to end, a
		// failed random read): the session keeps its map, and the next sync
		// tries again.
		if sink.logger != nil && !errors.Is(err, errNoFlowTicket) && !sink.flowWarned.Swap(true) {
			sink.logger.Warn("connection log ticket not signed", "error_code", "flow_ticket_unsigned")
		}
		return time.Time{}, nil
	}
	if err := sink.session.Send(sharedmtcp.MessageFlowTicket, ticket); err != nil {
		return time.Time{}, err
	}
	sink.flowSent.Store(true)
	return expires, nil
}

// withdrawFlowTicket turns logging off before the map's authority is
// paused or withdrawn, when the node holds a token this sink sent: a token
// outlives the stream by up to its 15 minutes.
func (sink *mapSink) withdrawFlowTicket() error {
	if !sink.flowSent.Swap(false) {
		return nil
	}
	return sink.session.Send(sharedmtcp.MessageFlowTicket, &mtcpv1.FlowTicket{})
}
