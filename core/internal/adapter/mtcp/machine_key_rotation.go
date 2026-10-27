package mtcp

import (
	"context"
	"errors"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// errMachineKeyRotated ends a session after its machine key changed: the
// gateway reconnects with the new key (mtcp-v1 §6.8).
var errMachineKeyRotated = errors.New("mtcp: machine key rotated")

// rotateMachineKey answers RotateMachineKey (mtcp-v1 §6.8): only a gateway
// session that proved its node key moves, to a key whose possession the
// request proves. The rotation commits even if the session ends meanwhile,
// so a pod that died during it finds the new key current.
func (conversation *conversation) rotateMachineKey(ctx context.Context, request *mtcpv1.RotateMachineKey) error {
	rotations := conversation.application.options.MachineKeyRotations
	if rotations == nil {
		return conversation.sendError(mtcpv1.Error_UNSUPPORTED, "machine key rotation is not available", 0)
	}
	if !conversation.isGateway() {
		return conversation.sendError(mtcpv1.Error_NOT_PERMITTED,
			"only a Kubernetes gateway rotates its machine key", 0)
	}
	conversation.mu.Lock()
	proven := conversation.provenNodeKey
	conversation.mu.Unlock()
	if !proven.IsValid() {
		return conversation.sendError(mtcpv1.Error_NOT_AUTHORIZED, "the node key is not proven", 0)
	}
	current := node.MachineKey(conversation.session.Machine())
	raw := request.GetNewMachineKey()
	// Bit 255 set is another spelling of the same X25519 key, with another
	// fingerprint: refused, so no key is used twice under two names.
	if len(raw) != key.Size || raw[key.Size-1]&0x80 != 0 || !sharedmtcp.VerifyMachineKeyRotationProof(conversation.session.control,
		conversation.session.HandshakeHash(), [key.Size]byte(raw), request.GetProof()) {
		return conversation.sendError(mtcpv1.Error_INVALID, "the new machine key or its proof is invalid", 0)
	}
	next := node.MachineKey(raw)
	if !next.IsValid() || next == current {
		return conversation.sendError(mtcpv1.Error_INVALID, "the new machine key or its proof is invalid", 0)
	}
	// K1.1: the pod's token first, before Redis or the store.
	token, ok := conversation.gatewayRotationToken(ctx, request.GetServiceAccountToken(), current, proven)
	if !ok {
		return conversation.refuseGatewayRotation()
	}
	operation, err := publicid.New()
	if err != nil {
		return conversation.sendError(mtcpv1.Error_INTERNAL, "rotation unavailable", 2000)
	}
	// Checked last, right before the stream stops and the rotation commits.
	claim, allowed := conversation.gatewayMayRotate(ctx)
	if !allowed {
		return conversation.refuseGatewayRotation()
	}
	// The lease stays the stream's while the rotation commits.
	conversation.keepGatewayPresence(claim)
	// The stream stops first: the committed rotation retires this
	// session's machine key, and the node must get the response, not an
	// EXPIRED from its own map stream. A refusal resumes it.
	nodeKey, disco, hostname := conversation.suspendStream()
	rotateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), registrationTimeout)
	defer cancel()
	err = rotations.RotateGatewayMachineKey(rotateCtx, kubecluster.MachineKeyRotation{
		MachineKey: current, NodeKey: proven, NewMachineKey: next, OperationID: operation, Token: token,
	})
	conversation.releaseGatewayPresence(ctx, claim)
	if err != nil && nodeKey.IsValid() {
		conversation.authorize(nodeKey, disco, hostname, false)
	}
	var limited *kubecluster.RotationLimitedError
	switch {
	case err == nil:
	// NOT_PERMITTED tells the node to discard the staged key: the rotation
	// surely did not commit.
	case errors.Is(err, kubecluster.ErrMachineKeyUsed):
		return conversation.sendError(mtcpv1.Error_NOT_PERMITTED, "the new machine key was used before", 0)
	case errors.Is(err, kubecluster.ErrGatewayTokenRefused):
		conversation.application.options.Metrics.limited(limitGatewayTokenStore)
		return conversation.refuseGatewayRotation()
	case errors.As(err, &limited):
		return conversation.sendError(mtcpv1.Error_NOT_PERMITTED,
			"the gateway changed its machine key too often; try again later", retryAfterMS(limited.RetryAfter))
	case errors.Is(err, kubecluster.ErrNotFound):
		return conversation.sendError(mtcpv1.Error_NOT_AUTHORIZED, "the keys are no longer the gateway's", 0)
	default:
		if ctx.Err() == nil {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp machine key rotation failed",
				"error_code", "machine_key_rotation_unavailable")
		}
		return conversation.sendError(mtcpv1.Error_INTERNAL, "rotation unavailable", 2000)
	}
	if err := conversation.session.Send(sharedmtcp.MessageRotateMachineKeyResponse,
		&mtcpv1.RotateMachineKeyResponse{}); err != nil {
		return err
	}
	return errMachineKeyRotated
}
