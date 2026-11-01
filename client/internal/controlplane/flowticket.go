package controlplane

import (
	"context"
	"time"

	"meshtransit.net/shared/key"
)

// FlowTicket is Core's leave to send connection logs (mtcp-v1 §9.1). An
// empty Token turns logging off. It is valid until the token's own expiry,
// across sessions; NotAfter says when the next ticket is due.
type FlowTicket struct {
	Token       []byte
	ReceiverKey []byte
	NotAfter    time.Time
	// Machine is the key the token is bound to: the requests' Noise static
	// key (flowlog-v1 §4).
	Machine key.MachinePrivate
	// Post sends one request to the control origin's fixed connection log
	// path (ADR-054) and returns the receiver's plain HTTP answer.
	Post func(ctx context.Context, tokenHeader string, body []byte) (FlowPostResult, error)
}

// FlowPostResult is the receiver's HTTP answer: only a 200 body is a sealed
// answer (flowlog-v1 §4).
type FlowPostResult struct {
	Status     int
	Body       []byte
	RetryAfter time.Duration
}
