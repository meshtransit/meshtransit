// Package kubecluster models Kubernetes clusters whose gateways join a
// Network (K1 design §3, §4.1): the cluster, its join keys and the requests
// replicas make to join, which an administrator approves by typing the code
// the replica prints. A request holds no Device: the Device exists only after
// approval, so a leaked join key alone never makes anyone a gateway.
package kubecluster

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalid reports malformed input or stored state.
	ErrInvalid = errors.New("kubernetes cluster: invalid")
	// ErrTransition reports a request change its state does not allow.
	ErrTransition = errors.New("kubernetes cluster: invalid request transition")
	// ErrExpired reports a request past its deadline.
	ErrExpired = errors.New("kubernetes cluster: request expired")
)

const (
	// MaximumNameLength leaves room in one DNS label (63) for the replica
	// suffix "-<ordinal>".
	MaximumNameLength = 60
	// MaximumDescriptionLength bounds a description, in characters.
	MaximumDescriptionLength = 128
	// MinimumJoinKeyLifetime is the shortest validity of a join key.
	MinimumJoinKeyLifetime = 5 * time.Minute
	// MaximumJoinKeyLifetime is the longest: a leaked key is useful for at
	// most an hour, and only with an approval (design §4.1).
	MaximumJoinKeyLifetime = time.Hour
	// DefaultJoinKeyLifetime is used when a request names none.
	DefaultJoinKeyLifetime = time.Hour
	// MaximumJoinKeyUses bounds the replicas one key can add.
	MaximumJoinKeyUses = 8
	// MaximumCodeAttempts wrong codes cancel a request.
	MaximumCodeAttempts = 5
	// MaximumOrdinal is the highest replica ordinal.
	MaximumOrdinal = 63
)

// ID identifies one cluster.
type ID publicid.ID

// ParseID validates a canonical cluster UUIDv7.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalid
	}
	return ID(id), nil
}

// String returns the canonical public identity.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the identity is a UUIDv7.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }

// RequestID identifies one replica request.
type RequestID publicid.ID

// ParseRequestID validates a canonical request UUIDv7.
func ParseRequestID(value string) (RequestID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return RequestID{}, ErrInvalid
	}
	return RequestID(id), nil
}

// String returns the canonical public identity.
func (id RequestID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the identity is a UUIDv7.
func (id RequestID) IsValid() bool { return publicid.ID(id).IsValid() }

// Name is a cluster's name: a DNS label, unique in its Network, used in the
// cluster's mesh DNS name and kubeconfig contexts.
type Name string

// ParseName accepts a lowercase DNS label: letters, digits and inner
// hyphens, 1 to 60 characters.
func ParseName(value string) (Name, error) {
	if value == "" || len(value) > MaximumNameLength || value[0] == '-' || value[len(value)-1] == '-' {
		return "", ErrInvalid
	}
	for index := range len(value) {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return "", ErrInvalid
		}
	}
	return Name(value), nil
}

// String returns the name.
func (name Name) String() string { return string(name) }

// ValidDescription accepts a trimmed, bounded description of plain text,
// or none.
func ValidDescription(description string) bool {
	return utf8.ValidString(description) && utf8.RuneCountInString(description) <= MaximumDescriptionLength &&
		description == strings.TrimSpace(description) &&
		!strings.ContainsFunc(description, func(character rune) bool { return character < 0x20 || character == 0x7f })
}

// ValidJoinKey accepts a key lifetime of whole seconds from five minutes to
// an hour, or zero for the default, and 1 to 8 uses.
func ValidJoinKey(lifetime time.Duration, uses int) bool {
	if lifetime == 0 {
		lifetime = DefaultJoinKeyLifetime
	}
	return lifetime >= MinimumJoinKeyLifetime && lifetime <= MaximumJoinKeyLifetime &&
		lifetime%time.Second == 0 && uses >= 1 && uses <= MaximumJoinKeyUses
}

// MaximumPendingRequests bounds the requests a key with uses uses may have
// waiting at once: junk requests from a leaked key fill only this queue.
func MaximumPendingRequests(uses int) int { return 2 * uses }

// RequestState is a replica request's lifecycle.
type RequestState string

// Request states. Approved requests become completed when the replica's
// session creates the Device; the others are terminal.
const (
	RequestPending   RequestState = "pending"
	RequestApproved  RequestState = "approved"
	RequestCompleted RequestState = "completed"
	RequestRejected  RequestState = "rejected"
	RequestExpired   RequestState = "expired"
	RequestCancelled RequestState = "cancelled"
)

// IsKnown reports a state a request can have.
func (state RequestState) IsKnown() bool {
	switch state {
	case RequestPending, RequestApproved, RequestCompleted, RequestRejected, RequestExpired, RequestCancelled:
		return true
	default:
		return false
	}
}

// RequestParams rehydrates a Request's lifecycle from storage.
type RequestParams struct {
	State          RequestState
	FailedAttempts int
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// Request is the lifecycle of one replica's request to join a cluster.
type Request struct {
	state          RequestState
	failedAttempts int
	createdAt      time.Time
	expiresAt      time.Time
}

// NewRequest validates stored request state.
func NewRequest(params RequestParams) (Request, error) {
	if !params.State.IsKnown() || params.CreatedAt.IsZero() || !params.ExpiresAt.After(params.CreatedAt) ||
		params.FailedAttempts < 0 || params.FailedAttempts > MaximumCodeAttempts ||
		(params.FailedAttempts == MaximumCodeAttempts && params.State != RequestCancelled) {
		return Request{}, ErrInvalid
	}
	return Request{
		state: params.State, failedAttempts: params.FailedAttempts,
		createdAt: params.CreatedAt.UTC(), expiresAt: params.ExpiresAt.UTC(),
	}, nil
}

// State returns the request's state.
func (request Request) State() RequestState { return request.state }

// FailedAttempts returns how many wrong codes were typed.
func (request Request) FailedAttempts() int { return request.failedAttempts }

// CreatedAt returns when the replica asked.
func (request Request) CreatedAt() time.Time { return request.createdAt }

// ExpiresAt returns the request's exclusive deadline, its key's expiry.
func (request Request) ExpiresAt() time.Time { return request.expiresAt }

func (request Request) pendingAt(now time.Time) error {
	if request.state != RequestPending {
		return ErrTransition
	}
	if now.IsZero() {
		return ErrInvalid
	}
	if !now.Before(request.expiresAt) {
		return ErrExpired
	}
	return nil
}

// Approve records a correct code on a pending request before its deadline.
func (request Request) Approve(now time.Time) (Request, error) {
	if err := request.pendingAt(now); err != nil {
		return Request{}, err
	}
	request.state = RequestApproved
	return request, nil
}

// WrongCode counts a wrong code on a pending request; the last allowed
// attempt cancels it.
func (request Request) WrongCode(now time.Time) (Request, error) {
	if err := request.pendingAt(now); err != nil {
		return Request{}, err
	}
	request.failedAttempts++
	if request.failedAttempts >= MaximumCodeAttempts {
		request.state = RequestCancelled
	}
	return request, nil
}

// Reject ends a pending request by an administrator's decision.
func (request Request) Reject() (Request, error) {
	if request.state != RequestPending {
		return Request{}, ErrTransition
	}
	request.state = RequestRejected
	return request, nil
}

// Complete records that the approved replica's Device now exists.
func (request Request) Complete() (Request, error) {
	if request.state != RequestApproved {
		return Request{}, ErrTransition
	}
	request.state = RequestCompleted
	return request, nil
}
