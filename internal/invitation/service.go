package invitation

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// Store applies one change or lists a Workspace's invitations; PostgreSQL
// authorizes both. PreviewInvitation answers only a pending, unexpired
// invitation for the digest.
type Store interface {
	Change(ctx context.Context, change Change) (ChangeResult, error)
	List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID, now time.Time) (
		[]Invitation, error)
	PreviewInvitation(ctx context.Context, digest [32]byte, now time.Time) (Preview, error)
}

// Preview is what the holder of a link sees before signing in.
type Preview struct {
	WorkspaceName string
	InviterName   string
	Email         string
	Role          string
	ExpiresAt     time.Time
}

// Preview reads the invitation a link names. Any problem with the token is
// ErrNotFound, so a link reveals nothing more than that it works.
func (service *Service) Preview(ctx context.Context, token Token) (Preview, error) {
	if ctx == nil || service == nil || !token.IsValid() {
		return Preview{}, ErrNotFound
	}
	preview, err := service.store.PreviewInvitation(ctx, token.Digest(), service.clock.Now().UTC())
	if errors.Is(err, ErrInvalid) {
		return Preview{}, ErrNotFound
	}
	return preview, err
}

// Mailer delivers one rendered message (SES API or SMTP).
type Mailer interface {
	Send(ctx context.Context, mail Mail) error
}

// Clock supplies the current time.
type Clock interface{ Now() time.Time }

// Options compose a service. Mailer is optional: without one, invitations
// are created and their links shown, but nothing is emailed.
type Options struct {
	Store         Store
	Mailer        Mailer
	Clock         Clock
	ConsoleOrigin string
	SendTimeout   time.Duration
	Logger        *slog.Logger
}

// Service creates, resends, revokes and lists invitations and emails them.
type Service struct {
	store       Store
	mailer      Mailer
	clock       Clock
	origin      string
	sendTimeout time.Duration
	logger      *slog.Logger
}

// NewService validates its dependencies and the exact Console origin.
func NewService(options Options) (*Service, error) {
	origin, err := url.Parse(options.ConsoleOrigin)
	if options.Store == nil || options.Clock == nil || options.Logger == nil || err != nil ||
		origin.Scheme != "https" || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" ||
		origin.Fragment != "" || origin.User != nil || options.SendTimeout <= 0 || options.SendTimeout > time.Minute {
		return nil, ErrInvalid
	}
	return &Service{
		store: options.Store, mailer: options.Mailer, clock: options.Clock, origin: origin.String(),
		sendTimeout: options.SendTimeout, logger: options.Logger,
	}, nil
}

// MailConfigured reports whether invitations are emailed.
func (service *Service) MailConfigured() bool { return service != nil && service.mailer != nil }

// CreateRequest names an invitation to create.
type CreateRequest struct {
	WorkspaceID   workspace.ID
	Email         string
	Role          string
	CorrelationID publicid.ID
}

// ActionRequest names a change to one invitation at the version read.
type ActionRequest struct {
	WorkspaceID     workspace.ID
	InvitationID    publicid.ID
	ExpectedVersion int64
	CorrelationID   publicid.ID
}

// Sent is an invitation with the link it was sent with; the link is shown to
// the inviter once and never stored.
type Sent struct {
	Invitation Invitation
	Link       string
}

func (service *Service) now(session accountsession.Session) (time.Time, error) {
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return time.Time{}, ErrForbidden
	}
	return now, nil
}

// Create invites one address and emails the link.
func (service *Service) Create(ctx context.Context, session accountsession.Session, request CreateRequest) (
	Sent, error) {
	if ctx == nil || service == nil {
		return Sent{}, ErrInvalid
	}
	now, err := service.now(session)
	if err != nil {
		return Sent{}, err
	}
	email, ok := NormalizeEmail(request.Email)
	if !ok || (request.Role != "" && roleLabels[request.Role] == "") {
		return Sent{}, ErrInvalid
	}
	id, err := publicid.New()
	if err != nil {
		return Sent{}, ErrUnavailable
	}
	return service.rotate(ctx, Change{
		Session: session, WorkspaceID: request.WorkspaceID, InvitationID: id, Action: ActionCreate, Email: email,
		Role: request.Role, CorrelationID: request.CorrelationID, EvaluatedAt: now,
	})
}

// Resend rotates the token, extends the expiry and emails the new link.
func (service *Service) Resend(ctx context.Context, session accountsession.Session, request ActionRequest) (
	Sent, error) {
	if ctx == nil || service == nil {
		return Sent{}, ErrInvalid
	}
	now, err := service.now(session)
	if err != nil {
		return Sent{}, err
	}
	return service.rotate(ctx, Change{
		Session: session, WorkspaceID: request.WorkspaceID, InvitationID: request.InvitationID,
		Action: ActionResend, ExpectedVersion: request.ExpectedVersion, CorrelationID: request.CorrelationID,
		EvaluatedAt: now,
	})
}

// Revoke ends a pending invitation; its link stops working.
func (service *Service) Revoke(ctx context.Context, session accountsession.Session, request ActionRequest) (
	Invitation, error) {
	if ctx == nil || service == nil {
		return Invitation{}, ErrInvalid
	}
	now, err := service.now(session)
	if err != nil {
		return Invitation{}, err
	}
	change := Change{
		Session: session, WorkspaceID: request.WorkspaceID, InvitationID: request.InvitationID,
		Action: ActionRevoke, ExpectedVersion: request.ExpectedVersion, CorrelationID: request.CorrelationID,
		EvaluatedAt: now,
	}
	if !change.IsValid() {
		return Invitation{}, ErrInvalid
	}
	result, err := service.store.Change(ctx, change)
	if err != nil {
		return Invitation{}, err
	}
	return result.Invitation, nil
}

// List returns pending invitations and those settled in the last 30 days.
func (service *Service) List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID) (
	[]Invitation, error) {
	if ctx == nil || service == nil || !workspaceID.IsValid() {
		return nil, ErrInvalid
	}
	now, err := service.now(session)
	if err != nil {
		return nil, err
	}
	return service.store.List(ctx, session, workspaceID, now)
}

// rotate commits a fresh token digest, then sends the link and records how
// delivery went. A delivery failure leaves the invitation pending with
// delivery_state failed; the inviter still has the link.
func (service *Service) rotate(ctx context.Context, change Change) (Sent, error) {
	token, err := NewToken()
	if err != nil {
		return Sent{}, err
	}
	digest := token.Digest()
	change.TokenDigest, change.ExpiresAt = &digest, expiresAt(change.EvaluatedAt)
	if !change.IsValid() {
		return Sent{}, ErrInvalid
	}
	result, err := service.store.Change(ctx, change)
	if err != nil {
		return Sent{}, err
	}
	link := service.origin + "/join#invite=" + token.String()
	sent := Sent{Invitation: result.Invitation, Link: link}
	outcome := ActionNotConfigured
	if service.mailer != nil {
		outcome = ActionDelivered
		if err := service.send(ctx, result, link); err != nil {
			outcome = ActionDeliveryFailed
			// Transports report only a stable code or kind, never an address.
			service.logger.WarnContext(ctx, "invitation email not delivered",
				"invitation_id", result.Invitation.ID.String(), "error_class", deliveryClass(err),
				"error", err.Error())
		}
	}
	recorded, err := service.store.Change(ctx, Change{
		Session: change.Session, WorkspaceID: change.WorkspaceID, InvitationID: result.Invitation.ID,
		Action: outcome, ExpectedVersion: result.Invitation.Version, CorrelationID: change.CorrelationID,
		EvaluatedAt: change.EvaluatedAt,
	})
	if err != nil {
		// The invitation and its link stand; only the delivery record is late.
		service.logger.WarnContext(ctx, "invitation delivery outcome not recorded",
			"invitation_id", result.Invitation.ID.String(), "outcome", string(outcome))
		return sent, nil
	}
	sent.Invitation = recorded.Invitation
	return sent, nil
}

func (service *Service) send(ctx context.Context, result ChangeResult, link string) error {
	mail, err := render(result.Invitation, result.WorkspaceName, link)
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, service.sendTimeout)
	defer cancel()
	return service.mailer.Send(sendCtx, mail)
}

// deliveryClass is a bounded label for logs.
func deliveryClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrMailRejected):
		return "rejected"
	default:
		return "unavailable"
	}
}

// ErrMailRejected is what a Mailer wraps for a message the transport will
// not send as it is; other errors may pass on a later attempt.
var ErrMailRejected = errors.New("invitation: email rejected")
