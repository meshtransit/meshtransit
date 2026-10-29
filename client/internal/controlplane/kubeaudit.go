package controlplane

import (
	"errors"
	"time"
)

// Kubernetes operation records (MTCP gateway.audit1, mtcp-v1 §6.10; K1b0,
// K1b design §7). A gateway has Core record each type A operation before
// it forwards it, on the session of its map stream; outcomes and denials
// follow, unanswered.

var (
	// ErrKubeAuditUnsupported: the session's Core did not offer
	// gateway.audit1.
	ErrKubeAuditUnsupported = errors.New("control plane: Core does not record Kubernetes operations")
	// ErrKubeAuditSessionLost: the session ended before the ack; the
	// intents may be recorded, and sending them again finds them.
	ErrKubeAuditSessionLost = errors.New("control plane: the session ended before the operations' ack")
	// ErrKubeAuditTimeout: no ack by the call's deadline.
	ErrKubeAuditTimeout = errors.New("control plane: no operations' ack in time")
	// ErrKubeAuditBusy: as many batches as Core takes wait on the session.
	ErrKubeAuditBusy = errors.New("control plane: too many operation batches wait")
	// ErrKubeAuditAck: Core's ack did not answer the batch it names.
	ErrKubeAuditAck = errors.New("control plane: an operations' ack out of form")
	// ErrKubeAuditBatch: the batch is not one the stream may send (no
	// intents, too many, an unknown class, over the message's size).
	ErrKubeAuditBatch = errors.New("control plane: an operation batch out of bounds")
)

// KubeAuditIntent is one type A operation as the gateway describes it to
// Core (KubeAuditIntent, mtcp-v1 §6.10).
type KubeAuditIntent struct {
	// ID is in the UUIDv7 layout, by Core's clock: Core answers the same
	// audit_id for the same ID and content within its window.
	ID           [16]byte
	Peer         string // the Device's public ID
	Groups       []string
	Class        string // write, exec, proxy, secret_read, privileged or unparsed
	Verb         string
	APIGroup     string
	Resource     string
	Subresource  string
	Namespace    string
	Name         string
	Impersonated string
	TokenID      []byte
	ObservedAt   time.Time
}

// KubeAuditBatch is up to 128 intents sent together.
type KubeAuditBatch struct {
	ID      [16]byte
	Intents []KubeAuditIntent
}

// KubeAuditResult is Core's answer to one intent: its audit_id when
// recorded, else why not and when to send it again.
type KubeAuditResult struct {
	IntentID   [16]byte
	AuditID    [16]byte
	Refused    string // empty: recorded
	RetryAfter time.Duration
}

// Recorded reports an intent Core recorded.
func (result KubeAuditResult) Recorded() bool { return result.Refused == "" }

// KubeAuditCall hands one batch to the map stream; Reply, buffered with
// room for one, receives at most one answer (the stream never waits on it).
// A call still unanswered at Deadline is answered ErrKubeAuditTimeout; one
// unsent by then is never sent.
type KubeAuditCall struct {
	Batch    KubeAuditBatch
	Reply    chan<- KubeAuditReply
	Deadline time.Time
}

// KubeAuditReply is a call's answer: a result per intent, in order, or why
// there are none.
type KubeAuditReply struct {
	Results []KubeAuditResult
	Err     error
}

// KubeAuditOutcome is a forwarded operation's result: its HTTP status (0:
// not forwarded after all, its ack came too late) and duration.
type KubeAuditOutcome struct {
	AuditID  [16]byte
	Status   int
	Duration time.Duration
}

// KubeAuditDenials counts requests of one peer the gateway refused itself,
// for one reason (type B), over First to Last.
type KubeAuditDenials struct {
	Peer        string // empty: not named
	Reason      string // unauthenticated, forbidden, not_granted, stale, limited or other
	Count       int
	First, Last time.Time
}

// KubeAuditReport is at most 1,024 outcomes and 256 denials, sent
// unanswered; the stream drops one it cannot send.
type KubeAuditReport struct {
	Outcomes []KubeAuditOutcome
	Denials  []KubeAuditDenials
}
