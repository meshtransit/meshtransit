package kubecluster

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrCARetired reports a CA already retired: nothing to ask for.
	ErrCARetired = errors.New("kubernetes cluster: the CA is already retired")
	// ErrRetirePending reports another request to retire the CA, for
	// another reason, still waiting (K1d Q158).
	ErrRetirePending = errors.New("kubernetes cluster: another request to retire the CA is waiting")
	// ErrRetireRateLimited reports a person's sixth request within the hour
	// (K1d Q157).
	ErrRetireRateLimited = errors.New("kubernetes cluster: too many requests to retire CAs")
)

// Bounds of a retire request (K1d §4.1).
const (
	MaximumRetireTextLength = 256
	RetireRequestLifetime   = time.Hour
	MaximumRetirePerHour    = 5
)

// Why a CA is retired at a person's request, as the worker's command takes
// it.
const (
	RetireReasonAdmin      = "admin"
	RetireReasonEmergency  = "emergency"
	RetireReasonCompromise = "compromise"
)

// How a request ended; RetireRefusal says why the worker refused it.
const (
	RetireStatePending = "pending"
	RetireStateDone    = "done"
	RetireStateRefused = "refused"
)

// Why the worker refused a request (K1d §4.1): it waited past its hour,
// the CA moved past the version asked for, the restore guard was on for a
// reason other than compromise, or the CA is gone.
const (
	RetireRefusalExpired = "expired"
	RetireRefusalChanged = "changed"
	RetireRefusalGuard   = "guard"
	RetireRefusalGone    = "gone"
)

// ValidRetireReason reports a reason a person may give.
func ValidRetireReason(reason string) bool {
	return reason == RetireReasonAdmin || reason == RetireReasonEmergency || reason == RetireReasonCompromise
}

// validRetireText reports printable text of at most 256 characters, empty
// allowed only where allowEmpty says so; Core checks the same.
func validRetireText(text string, allowEmpty bool) bool {
	if text == "" {
		return allowEmpty
	}
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > MaximumRetireTextLength {
		return false
	}
	// Invisible format and separator characters could make one reference
	// look like another in the Console or a SIEM (review d2a L8).
	return !strings.ContainsFunc(text, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
	})
}

// CARetireRequest is a person's request to retire one of a cluster's CAs.
type CARetireRequest struct {
	ID          publicid.ID
	CAID        publicid.ID
	CAVersion   int64
	Reason      string
	ChangeRef   string
	Note        string
	RequestedBy publicid.ID
	State       string
	Refusal     string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	FinishedAt  time.Time
}

// CARetireRequestCommand asks to retire a CA at the version read
// (kubernetes_cluster.approve).
type CARetireRequestCommand struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	CAID          publicid.ID
	CAVersion     int64
	Reason        string
	ChangeRef     string
	Note          string
	CorrelationID publicid.ID
}

// CARetireRequestResult is the request recorded, or the one already
// waiting for the same CA and reason (Created false).
type CARetireRequestResult struct {
	Request CARetireRequest
	Created bool
}

// CARetireRequestPage is a page of a cluster's requests, newest first.
type CARetireRequestPage struct {
	Requests []CARetireRequest
	Next     PageCursor
}

// RequestCARetire records a request for the CA worker to retire a CA; it
// never changes the CA itself.
func (service *Service) RequestCARetire(ctx context.Context,
	command CARetireRequestCommand) (CARetireRequestResult, error) {
	if err := service.admit(ctx, command.Session, command.Scope); err != nil {
		return CARetireRequestResult{}, err
	}
	if !command.ClusterID.IsValid() || !command.CAID.IsValid() || command.CAVersion < 1 ||
		!ValidRetireReason(command.Reason) || !validRetireText(command.ChangeRef, false) ||
		!validRetireText(command.Note, true) || !command.CorrelationID.IsValid() {
		return CARetireRequestResult{}, ErrInvalid
	}
	return service.store.RequestCARetire(ctx, command)
}

// ListCARetireRequests returns a page of a cluster's requests
// (kubernetes_cluster.approve or audit.read).
func (service *Service) ListCARetireRequests(ctx context.Context, query PageQuery) (CARetireRequestPage, error) {
	if err := service.admitPage(ctx, query); err != nil {
		return CARetireRequestPage{}, err
	}
	return service.store.ListCARetireRequests(ctx, query)
}
