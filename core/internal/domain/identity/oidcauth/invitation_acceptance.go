package oidcauth

import (
	"context"
	"errors"
	"log/slog"
)

var (
	// ErrInvitationRejected reports an invitation that cannot be accepted by
	// this sign-in: unknown, used, revoked, expired, a suspended member, or a
	// sign-in whose provider did not verify the invited address.
	ErrInvitationRejected = errors.New("oidcauth: invitation rejected")
	// ErrInvitationUnavailable reports a dependency failure while accepting.
	ErrInvitationUnavailable = errors.New("oidcauth: invitation acceptance unavailable")
)

// InvitationProof is the digest of an invitation token that the browser
// presented for this sign-in. The zero value means no invitation.
type InvitationProof struct{ digest [32]byte }

// NewInvitationProof wraps a token digest.
func NewInvitationProof(digest [32]byte) InvitationProof { return InvitationProof{digest: digest} }

// IsValid reports a presented invitation.
func (proof InvitationProof) IsValid() bool { return proof.digest != [32]byte{} }

// Digest returns the token digest the store matches.
func (proof InvitationProof) Digest() [32]byte { return proof.digest }

// String redacts the digest.
func (InvitationProof) String() string { return "[REDACTED]" }

// LogValue redacts the digest.
func (InvitationProof) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// InvitationAcceptance binds one invitation to the exact consuming sign-in and
// the identity it proved.
type InvitationAcceptance struct {
	Lookup SubjectLookup
	Proof  InvitationProof
	// Email is the address the provider marked verified for this sign-in.
	// The invitation is accepted only when it equals the invited address.
	Email string
}

// InvitationAcceptor makes the signed-in identity a member through the
// invitation in one committed unit, before the subject is resolved.
type InvitationAcceptor interface {
	AcceptInvitation(ctx context.Context, acceptance InvitationAcceptance) error
}

// acceptInvitation runs between the exchange and subject resolution.
func (service *CallbackService) acceptInvitation(ctx context.Context, exchange ExchangeResult,
	proof InvitationProof) error {
	if service.invitations == nil || service.subjectKeys == nil {
		return ErrInvitationRejected
	}
	digests, err := service.subjectKeys.Digests(exchange.claimed.snapshot.Route(), exchange.identity)
	if err != nil {
		return ErrInvitationRejected
	}
	lookup, err := NewSubjectLookup(exchange.claimed, digests)
	if err != nil {
		return ErrInvitationRejected
	}
	// The link names one address. Without an address the provider verified,
	// this sign-in cannot show it is that person, so the link is not used.
	email := exchange.identity.Profile().Email()
	if email == "" {
		return ErrInvitationRejected
	}
	acceptance := InvitationAcceptance{Lookup: lookup, Proof: proof, Email: email}
	if err := service.invitations.AcceptInvitation(ctx, acceptance); err != nil {
		if errors.Is(err, ErrInvitationRejected) {
			return ErrInvitationRejected
		}
		return ErrInvitationUnavailable
	}
	return nil
}
