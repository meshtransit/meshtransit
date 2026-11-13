package mtcp

import (
	"context"
	"errors"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// CapabilitySiblings is register.siblings1: a browser sign-in may list the
// machine's other profiles' machine keys with proofs, and Core answers
// already_in_network instead of making a second Device for the same person
// in the same Network (mtcp-v1 §6.2, duplicate-device design).
const CapabilitySiblings = "register.siblings1"

// maxSiblings bounds RegisterRequest.siblings (mtcp-v1 §6.2).
const maxSiblings = 16

// SiblingRecorder keeps a pending sign-in's proven sibling keys
// (control.BrowserRegistrationService). Optional on BrowserIssuer.
type SiblingRecorder interface {
	RecordSiblings(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key,
		approvalURL string, siblings [][32]byte) error
}

// SiblingCompleter is BrowserApproval with the siblings proven in the
// completing session (control.BrowserCompletionService). Optional.
type SiblingCompleter interface {
	CompleteBrowserWithSiblings(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key,
		hostname node.Hostname, followupURL string, siblings [][32]byte) (registration.Result, bool, error)
}

var tooManySiblings = rejection{code: mtcpv1.RegisterResponse_Rejected_INVALID,
	message: "too many sibling machine keys"}

// provenSiblings returns the sibling machine keys whose proofs hold in this
// session (mtcp-v1 §6.2): none without register.siblings1. Entries that are
// malformed, repeated, the session's own key, or whose proof fails are
// dropped; more than 16 is refused before any key agreement.
func (conversation *conversation) provenSiblings(request *mtcpv1.RegisterRequest) ([][32]byte, *rejection) {
	entries := request.GetSiblings()
	if len(entries) == 0 || !conversation.session.Supports(CapabilitySiblings) {
		return nil, nil
	}
	if len(entries) > maxSiblings {
		return nil, &tooManySiblings
	}
	own := conversation.session.Machine()
	hash := conversation.session.HandshakeHash()
	proven := make([][32]byte, 0, len(entries))
	for _, entry := range entries {
		raw := entry.GetMachineKey()
		if len(raw) != key.Size {
			conversation.application.options.Metrics.siblingProof(siblingDropped)
			continue
		}
		public := [key.Size]byte(raw)
		if public == own || public == [key.Size]byte{} || containsKey(proven, public) {
			conversation.application.options.Metrics.siblingProof(siblingDropped)
			continue
		}
		if !sharedmtcp.VerifySiblingMachineKeyProof(conversation.session.control, hash, public, entry.GetProof()) {
			conversation.application.options.Metrics.siblingProof(siblingInvalid)
			continue
		}
		conversation.application.options.Metrics.siblingProof(siblingValid)
		proven = append(proven, public)
	}
	return proven, nil
}

func containsKey(keys [][32]byte, public [32]byte) bool {
	for _, existing := range keys {
		if existing == public {
			return true
		}
	}
	return false
}

// recordSiblings keeps the proven siblings with the pending sign-in; a
// failure only loses the protection for this sign-in, and is logged.
func (conversation *conversation) recordSiblings(ctx context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, approvalURL string, siblings [][32]byte,
) {
	recorder, ok := conversation.application.options.BrowserIssuer.(SiblingRecorder)
	if !ok || len(siblings) == 0 {
		return
	}
	if err := recorder.RecordSiblings(ctx, machine, nodeKey, approvalURL, siblings); err != nil && ctx.Err() == nil {
		conversation.application.options.Logger.WarnContext(ctx, "recording browser sign-in siblings failed",
			"error", err)
	}
}

// completeBrowser completes with the session's siblings when the service
// takes them.
func (conversation *conversation) completeBrowser(ctx context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, hostname node.Hostname, followupURL string, siblings [][32]byte,
) (registration.Result, bool, error) {
	approval := conversation.application.options.BrowserApproval
	if completer, ok := approval.(SiblingCompleter); ok {
		return completer.CompleteBrowserWithSiblings(ctx, machine, nodeKey, hostname, followupURL, siblings)
	}
	return approval.CompleteBrowser(ctx, machine, nodeKey, hostname, followupURL)
}

// joinedExisting answers a sign-in the approver ended with "Use that
// account": already_in_network on a session that negotiated it, else
// rejected{CONFLICT} (mtcp-v1 §6.2). Ok is false for any other error.
func (conversation *conversation) joinedExisting(err error) (handled bool, sendErr error) {
	var joined *registration.JoinedExistingError
	if !errors.As(err, &joined) {
		return false, nil
	}
	conversation.application.options.Metrics.browserCompletion(completionAlreadyInNetwork)
	if !conversation.session.Supports(CapabilitySiblings) {
		return true, conversation.reject(siblingConflict)
	}
	return true, conversation.session.Send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
		Outcome: &mtcpv1.RegisterResponse_AlreadyInNetwork_{AlreadyInNetwork: &mtcpv1.RegisterResponse_AlreadyInNetwork{
			SiblingMachineKey: joined.SiblingMachineKey[:],
		}},
	})
}
