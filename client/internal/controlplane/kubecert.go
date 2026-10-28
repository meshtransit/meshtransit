package controlplane

import (
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"time"
)

// Kubernetes gateway replica certificates (MTCP gateway.cert1, mtcp-v1
// §6.9; K1a4a a4 design). A gateway asks over the session of its map
// stream, which holds its presence; the stream answers each call once.

var (
	// ErrKubeCertUnsupported: the session's Core did not offer
	// gateway.cert1.
	ErrKubeCertUnsupported = errors.New("control plane: Core does not issue gateway certificates")
	// ErrKubeCertSessionLost: the session ended before the answer; the
	// request may still be queued, and sending it again finds it.
	ErrKubeCertSessionLost = errors.New("control plane: the session ended before the certificate answer")
	// ErrKubeCertTimeout: no answer within the wait; sending the request
	// again finds it.
	ErrKubeCertTimeout = errors.New("control plane: no certificate answer in time")
	// ErrKubeCertBusy: another call of this gateway waits on the session.
	ErrKubeCertBusy = errors.New("control plane: another certificate request waits")
)

// KubeCertRequest is one certificate request. Exactly one proof: the pod's
// Token, or a renewal the stream signs, for the session that sends it, with
// RenewalKey, the key of the certificate whose serial is RenewalSerial
// (mtcp-v1 §6.9). Token and RenewalKey are credentials: KubeCertRequest
// never formats them.
type KubeCertRequest struct {
	RequestID     [16]byte
	CSR           []byte
	Token         string `json:"-"`
	RenewalSerial [16]byte
	RenewalKey    *ecdsa.PrivateKey `json:"-"`
}

// Renewal reports a request proved by the current certificate's key.
func (request KubeCertRequest) Renewal() bool { return request.RenewalKey != nil }

// String redacts the request, which may carry a token.
func (KubeCertRequest) String() string { return "controlplane.KubeCertRequest([REDACTED])" }

// GoString redacts detailed formatting.
func (KubeCertRequest) GoString() string { return "controlplane.KubeCertRequest([REDACTED])" }

// LogValue redacts structured formatting.
func (KubeCertRequest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// KubeCertOutcome is what Core answered.
type KubeCertOutcome uint8

// Outcomes; an outcome this build does not know is a retry.
const (
	KubeCertRetry KubeCertOutcome = iota
	KubeCertRefused
	KubeCertIssued
)

// KubeCertResult is Core's answer to one request.
type KubeCertResult struct {
	Outcome    KubeCertOutcome
	Reason     string
	RetryAfter time.Duration
	// Issued: the leaf and its intermediates (leaf side first), the
	// SHA-256 of the root's and the issuer's DER, and the Network revision
	// the certificate was issued at (0: unknown).
	Certificate       []byte
	Chain             [][]byte
	RootFingerprint   []byte
	IssuerFingerprint []byte
	NotAfter          time.Time
	RenewAt           time.Time
	NetworkRevision   uint64
}

// KubeCertCall hands one request to the map stream; Reply, buffered with
// room for one, receives at most one answer (the stream never waits on it:
// an answer it cannot hand over is dropped). A call still unsent at
// Deadline (zero: none) is answered ErrKubeCertTimeout, never sent.
type KubeCertCall struct {
	Request  KubeCertRequest
	Reply    chan<- KubeCertReply
	Deadline time.Time
}

// KubeCertReply is a call's answer: Core's result, or why there is none.
type KubeCertReply struct {
	Result KubeCertResult
	Err    error
}
