package oidcauth

import "errors"

// InvitationRefusal is why a sign-in could not use an invitation link, a
// closed set for metrics and logs: never the email, link or identity
// (TD-SEC-37). Someone trying a leaked link with another account shows as
// email_mismatch.
type InvitationRefusal uint8

const (
	// InvitationRefusalInvalid is a malformed request or one Core cannot key.
	InvitationRefusalInvalid InvitationRefusal = iota + 1
	// InvitationRefusalNoVerifiedEmail is a sign-in whose provider verified no email.
	InvitationRefusalNoVerifiedEmail
	// InvitationRefusalEmailMismatch is a verified email other than the invited one.
	InvitationRefusalEmailMismatch
	// InvitationRefusalNotPending is an unknown, used, revoked or expired link.
	InvitationRefusalNotPending
	// InvitationRefusalInviterAuthority is a link whose inviter no longer
	// may grant what it grants.
	InvitationRefusalInviterAuthority
	// InvitationRefusalMemberConflict is an invitee already a member in a way
	// the link cannot change (a role through an invitation, a suspension).
	InvitationRefusalMemberConflict
)

// String returns the metric label.
func (refusal InvitationRefusal) String() string {
	switch refusal {
	case InvitationRefusalInvalid:
		return "invalid"
	case InvitationRefusalNoVerifiedEmail:
		return "no_verified_email"
	case InvitationRefusalEmailMismatch:
		return "email_mismatch"
	case InvitationRefusalNotPending:
		return "not_pending"
	case InvitationRefusalInviterAuthority:
		return "inviter_authority"
	case InvitationRefusalMemberConflict:
		return "member_conflict"
	default:
		return "unknown"
	}
}

// InvitationRefusedError is ErrInvitationRejected with its reason.
type InvitationRefusedError struct{ Reason InvitationRefusal }

func (refused InvitationRefusedError) Error() string {
	return "oidcauth: invitation rejected: " + refused.Reason.String()
}

// Is makes the error match ErrInvitationRejected.
func (InvitationRefusedError) Is(target error) bool { return target == ErrInvitationRejected }

// RefuseInvitation returns ErrInvitationRejected carrying reason.
func RefuseInvitation(reason InvitationRefusal) error { return InvitationRefusedError{Reason: reason} }

// invitationRefusal reports err's reason; a bare ErrInvitationRejected is
// invalid.
func invitationRefusal(err error) InvitationRefusal {
	var refused InvitationRefusedError
	if errors.As(err, &refused) {
		return refused.Reason
	}
	return InvitationRefusalInvalid
}

// InvitationObserver counts refused invitation links by reason; it never
// sees the link, email or identity.
type InvitationObserver interface {
	InvitationRefused(InvitationRefusal)
}
