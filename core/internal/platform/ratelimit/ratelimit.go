// Package ratelimit owns secret-safe distributed rate-limit contracts.
package ratelimit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"
)

const (
	digestKeyBytes         = 32
	maximumKeyIDBytes      = 128
	maximumRawSubjectBytes = 256
	digestDomain           = "meshtransit/rate-limit-subject/v1\x00"
	maximumCapacity        = 1_000_000
	minimumRefillInterval  = 10 * time.Millisecond
	maximumRefillInterval  = 24 * time.Hour
)

var (
	// ErrInvalidDigestKey reports malformed HMAC key identity or material.
	ErrInvalidDigestKey = errors.New("rate limit: invalid digest key")
	// ErrInvalidSubject reports a missing or malformed rate-limit subject.
	ErrInvalidSubject = errors.New("rate limit: invalid subject")
	// ErrInvalidPolicy reports unsafe token-bucket bounds.
	ErrInvalidPolicy = errors.New("rate limit: invalid policy")
	// ErrInvalidDecision reports a malformed limiter result.
	ErrInvalidDecision = errors.New("rate limit: invalid decision")
)

// SubjectKind separates counters for distinct authority boundaries.
type SubjectKind string

const (
	// SubjectSource identifies the unauthenticated network-source budget.
	SubjectSource SubjectKind = "source"
	// SubjectAccountSession identifies the post-authentication session budget.
	SubjectAccountSession SubjectKind = "account_session"
	// SubjectAuthTransaction identifies a pre-authentication exact-state abuse budget, not authority.
	SubjectAuthTransaction SubjectKind = "auth_transaction"
	// SubjectNetworkChange identifies one person's budget for changes that
	// rebuild every map of one Network.
	SubjectNetworkChange SubjectKind = "network_change"
)

// DigestKeyID is the public version identifier for one HMAC key.
type DigestKeyID struct{ value string }

// NewDigestKeyID validates a bounded digest key identifier.
func NewDigestKeyID(value string) (DigestKeyID, error) {
	if !validKeyID(value) {
		return DigestKeyID{}, ErrInvalidDigestKey
	}
	return DigestKeyID{value: value}, nil
}

// String returns the non-secret digest key identifier.
func (id DigestKeyID) String() string { return id.value }

// IsValid reports whether the key identifier remains canonical.
func (id DigestKeyID) IsValid() bool {
	validated, err := NewDigestKeyID(id.value)
	return err == nil && validated == id
}

// Digester replaces raw source and session identities with purpose-separated HMACs.
type Digester struct {
	keyID    DigestKeyID
	material [digestKeyBytes]byte
}

// NewDigester validates and copies exactly 256 bits of HMAC key material.
func NewDigester(keyID DigestKeyID, material []byte) (*Digester, error) {
	if !keyID.IsValid() || len(material) != digestKeyBytes {
		return nil, ErrInvalidDigestKey
	}
	digester := &Digester{keyID: keyID}
	copy(digester.material[:], material)
	if digester.material == ([digestKeyBytes]byte{}) {
		return nil, ErrInvalidDigestKey
	}
	return digester, nil
}

// Subject validates and destroys one raw subject identity at the API boundary.
func (digester *Digester) Subject(kind SubjectKind, raw string) (Subject, error) {
	if digester == nil || !digester.keyID.IsValid() ||
		digester.material == ([digestKeyBytes]byte{}) {
		return Subject{}, ErrInvalidDigestKey
	}
	if !validSubjectKind(kind) || len(raw) == 0 || len(raw) > maximumRawSubjectBytes {
		return Subject{}, ErrInvalidSubject
	}
	mac := hmac.New(sha256.New, digester.material[:])
	_, _ = mac.Write([]byte(digestDomain))
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return Subject{kind: kind, keyID: digester.keyID.value, digest: digest}, nil
}

// String prevents accidental HMAC key disclosure.
func (*Digester) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed HMAC key disclosure.
func (*Digester) GoString() string { return "ratelimit.Digester([REDACTED])" }

// LogValue prevents accidental structured-log key disclosure.
func (*Digester) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Subject is a secret-safe distributed counter identity.
type Subject struct {
	kind   SubjectKind
	keyID  string
	digest [sha256.Size]byte
}

// Kind returns the bounded counter namespace.
func (subject Subject) Kind() SubjectKind { return subject.kind }

// DigestKeyID returns the non-secret HMAC key generation.
func (subject Subject) DigestKeyID() string { return subject.keyID }

// DigestString returns the base64url-encoded HMAC, never the raw identity.
func (subject Subject) DigestString() string {
	return base64.RawURLEncoding.EncodeToString(subject.digest[:])
}

// IsValid reports whether the subject remains canonical.
func (subject Subject) IsValid() bool {
	return validSubjectKind(subject.kind) && validKeyID(subject.keyID) &&
		subject.digest != ([sha256.Size]byte{})
}

// Policy defines a bounded token-bucket capacity and replenishment cadence.
type Policy struct {
	capacity       int64
	refillInterval time.Duration
}

// NewPolicy validates one rate-limit policy.
func NewPolicy(capacity int, refillInterval time.Duration) (Policy, error) {
	policy := Policy{capacity: int64(capacity), refillInterval: refillInterval}
	if !policy.IsValid() {
		return Policy{}, ErrInvalidPolicy
	}
	return policy, nil
}

// Capacity returns the maximum burst size.
func (policy Policy) Capacity() int64 { return policy.capacity }

// RefillInterval returns the time required to restore one token.
func (policy Policy) RefillInterval() time.Duration { return policy.refillInterval }

// IsValid reports whether the policy remains safely bounded.
func (policy Policy) IsValid() bool {
	return policy.capacity > 0 && policy.capacity <= maximumCapacity &&
		policy.refillInterval >= minimumRefillInterval &&
		policy.refillInterval <= maximumRefillInterval &&
		policy.refillInterval%time.Millisecond == 0
}

// Decision is one validated distributed limiter result.
type Decision struct {
	allowed    bool
	limit      int64
	remaining  int64
	retryAfter time.Duration
}

// NewDecision validates a limiter result before it crosses an adapter boundary.
func NewDecision(allowed bool, limit, remaining int64, retryAfter time.Duration) (Decision, error) {
	decision := Decision{allowed: allowed, limit: limit, remaining: remaining, retryAfter: retryAfter}
	if !decision.IsValid() {
		return Decision{}, ErrInvalidDecision
	}
	return decision, nil
}

// Allowed reports whether the request consumed one token.
func (decision Decision) Allowed() bool { return decision.allowed }

// Limit returns the configured burst capacity.
func (decision Decision) Limit() int64 { return decision.limit }

// Remaining returns the tokens immediately available after this decision.
func (decision Decision) Remaining() int64 { return decision.remaining }

// RetryAfter returns zero for admitted requests and a positive delay for denials.
func (decision Decision) RetryAfter() time.Duration { return decision.retryAfter }

// IsValid reports whether the decision can be exposed safely.
func (decision Decision) IsValid() bool {
	if decision.limit <= 0 || decision.remaining < 0 || decision.remaining > decision.limit {
		return false
	}
	if decision.allowed {
		return decision.retryAfter == 0
	}
	return decision.remaining == 0 && decision.retryAfter > 0
}

func validSubjectKind(kind SubjectKind) bool {
	return kind == SubjectSource || kind == SubjectAccountSession || kind == SubjectAuthTransaction ||
		kind == SubjectNetworkChange
}

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > maximumKeyIDBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == ':' ||
				character == '/' || character == '-')) {
			continue
		}
		return false
	}
	return true
}
