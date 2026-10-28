// Package certqueue is control's side of Kubernetes gateway replica
// certificates (K1a4a a3b, the a3 signing design §3, §14): a
// gateway's request is refused at once when no worker can sign, queued
// otherwise, and its session waits a few seconds for the worker to issue or
// refuse it. The worker checks every proof again; control only bounds and
// routes.
package certqueue

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// Reasons control answers with, beside the worker's and the database's
// (signing.Reason), which pass through. A gateway acts on each as §14.2
// says; one it does not know is a retry.
const (
	// Retry.
	ReasonUnavailable = "unavailable" // no worker can sign now
	ReasonBusy        = "busy"        // the session already waits for a request
	ReasonLimited     = "limited"
	ReasonOverloaded  = "overloaded"
	ReasonTimeout     = "timeout" // still queued; send it again
	ReasonPresence    = "presence"
	ReasonInternal    = "internal"
	// Refused.
	ReasonContested  = "contested"
	ReasonCSR        = "csr"
	ReasonInvalid    = "invalid" // the request's form: proofs, sizes
	ReasonConflict   = "conflict"
	ReasonNotGateway = "not_gateway"
	ReasonNotProven  = "not_proven"
)

// Outcome is what a gateway is told.
type Outcome uint8

// Outcomes.
const (
	OutcomeRetry Outcome = iota + 1
	OutcomeRefused
	OutcomeIssued
)

// State is where a request stands in the queue, or what queueing it said.
type State string

// States.
const (
	StatePending   State = "pending"
	StateClaimed   State = "claimed"
	StateIssued    State = "issued"
	StateRefused   State = "refused"
	StateAbandoned State = "abandoned"
	// StateLimited and StateConflict are answers to queueing only.
	StateLimited  State = "limited"
	StateConflict State = "conflict"
)

// Request is a gateway's certificate request as control queues it, for
// the keys the session proved. Exactly one of Token and the renewal
// (serial and proof) is set. Token is a bearer credential: Request never
// formats it.
type Request struct {
	ID                 publicid.ID // Core's, new for each request queued
	MachineFingerprint [32]byte
	NodeKey            [32]byte
	RequestID          [16]byte // the gateway's
	CSR                []byte
	PublicKeySHA256    [32]byte
	Token              string `json:"-"`
	HandshakeHash      [32]byte
	RenewalSerial      [16]byte
	RenewalProof       []byte
}

// Renewal reports a request proved by the current certificate's key.
func (request Request) Renewal() bool { return request.Token == "" }

// String redacts the request, which may carry a token.
func (Request) String() string { return "certqueue.Request([REDACTED])" }

// GoString redacts detailed formatting.
func (Request) GoString() string { return "certqueue.Request([REDACTED])" }

// LogValue redacts structured formatting.
func (Request) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Stored is a request as the queue holds it, or the answer to queueing it.
type Stored struct {
	State      State
	Reason     string
	RetryAfter time.Duration
	// Request and Device name the queued request (absent for an answer
	// that queued nothing).
	Request publicid.ID
	Device  publicid.ID
	// Issued.
	Certificate       []byte
	Chain             [][]byte
	RootFingerprint   []byte
	IssuerFingerprint []byte
	NotAfter          time.Time
	RenewAt           time.Time
	NetworkRevision   uint64
}

// SigningState is whether a worker can sign now.
type SigningState struct {
	SignerReady, RestoreSuspected, Checked bool
}

// Ready reports a worker that signs: its heartbeat holds, no restore is
// suspected and the restore tripwire was checked lately.
func (state SigningState) Ready() bool {
	return state.SignerReady && !state.RestoreSuspected && state.Checked
}

// ErrInvalid reports unsafe input or configuration.
var ErrInvalid = errors.New("kubernetes certificate queue: invalid")

// ErrNotProven reports a session whose keys are no longer a proven
// gateway's.
var ErrNotProven = errors.New("kubernetes certificate queue: no proven gateway session")

// Store is control's view of the queue (the postgres runtime store).
type Store interface {
	Enqueue(ctx context.Context, request Request) (Stored, error)
	// Read and Abandon report false when the request is gone (removed
	// after 10 minutes).
	Read(ctx context.Context, device, request publicid.ID) (Stored, bool, error)
	Abandon(ctx context.Context, device, request publicid.ID) (Stored, bool, error)
	SigningState(ctx context.Context) (SigningState, error)
}

// Result is what a gateway is told about one request.
type Result struct {
	Outcome    Outcome
	Reason     string
	RetryAfter time.Duration
	// Issued is the request as issued.
	Issued Stored
}

// KnownReasons is every reason a gateway may be told: control's, the
// worker's and the database's (schemas 240, 241). Metrics count any other
// as "other".
var KnownReasons = []string{
	ReasonUnavailable, ReasonBusy, ReasonLimited, ReasonOverloaded, ReasonTimeout, ReasonPresence,
	ReasonInternal, ReasonContested, ReasonCSR, ReasonConflict, ReasonNotGateway, ReasonNotProven,
	"no_ca", "misnamed", "trust_missing", "token", "token_expired", "token_used", "proof", "renewal_expired",
	"renewal_unknown", "revoked", "cluster", "attempts", "superseded", ReasonInvalid,
}

// KnownReason reports a reason in KnownReasons.
func KnownReason(reason string) bool {
	for _, known := range KnownReasons {
		if reason == known {
			return true
		}
	}
	return false
}
