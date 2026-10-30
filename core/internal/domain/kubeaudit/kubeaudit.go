// Package kubeaudit records the Kubernetes operations a gateway must have
// Core record before it forwards them (type A), and their outcomes and type
// B denials (K1b0 design; mtcp-v1 §6.10).
package kubeaudit

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/publicid"
)

// Class is the kind of a type A operation.
type Class string

// Classes (design §5.7 of the K1 design).
const (
	ClassWrite      Class = "write"
	ClassExec       Class = "exec"
	ClassProxy      Class = "proxy"
	ClassSecretRead Class = "secret_read"
	ClassPrivileged Class = "privileged"
	ClassUnparsed   Class = "unparsed"
)

// Bounds of an intent's fields (design §3.2), the same the schema checks.
const (
	MaximumIntents      = 128
	MaximumGroups       = 16
	maximumGroup        = 63
	maximumVerb         = 32
	maximumAPIGroup     = 253
	maximumResource     = 63
	maximumNamespace    = 63
	maximumName         = 253
	maximumImpersonated = 253
	maximumTokenID      = 32
	// intentWindow is how far an intent ID's milliseconds may be from Core's
	// clock: half the schema's 10-minute dedupe look-back, so an intent sent
	// again within it always meets the first (design §3.2, review b0a M6,
	// b0b2 L1).
	intentWindow = 5 * time.Minute
	// latestObserved is 9999-12-31T23:59:59.999Z, the schema's last.
	latestObserved = 253402300799999
)

// Intent is one type A operation as the gateway describes it.
type Intent struct {
	ID           [16]byte
	Peer         publicid.ID
	Groups       []string
	Class        Class
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

// Valid reports an intent whose every field is in form at now (design
// §3.3): known class, bounded UTF-8 without NUL or control characters, and
// an ID in the UUIDv7 layout whose milliseconds lie within intentWindow of
// now.
func (intent Intent) Valid(now time.Time) bool {
	switch intent.Class {
	case ClassWrite, ClassExec, ClassProxy, ClassSecretRead, ClassPrivileged, ClassUnparsed:
	default:
		return false
	}
	if !intent.Peer.IsValid() || len(intent.Groups) > MaximumGroups || len(intent.TokenID) > maximumTokenID ||
		intent.ObservedAt.IsZero() || intent.ObservedAt.UnixMilli() < 0 || intent.ObservedAt.UnixMilli() > latestObserved {
		return false
	}
	for _, group := range intent.Groups {
		if !cleanText(group, 1, maximumGroup) {
			return false
		}
	}
	for _, field := range []struct {
		value         string
		minimum, most int
	}{
		{intent.Verb, 1, maximumVerb}, {intent.APIGroup, 0, maximumAPIGroup},
		{intent.Resource, 0, maximumResource}, {intent.Subresource, 0, maximumResource},
		{intent.Namespace, 0, maximumNamespace}, {intent.Name, 0, maximumName},
		{intent.Impersonated, 0, maximumImpersonated},
	} {
		if !cleanText(field.value, field.minimum, field.most) {
			return false
		}
	}
	return intentIDInWindow(intent.ID, now)
}

// intentIDInWindow reports an ID in the UUIDv7 layout (version 7, variant
// 10) whose first 48 bits are milliseconds within intentWindow of now.
func intentIDInWindow(id [16]byte, now time.Time) bool {
	if id[6]>>4 != 7 || id[8]>>6 != 2 {
		return false
	}
	var millis [8]byte
	copy(millis[2:], id[:6])
	at := time.UnixMilli(int64(binary.BigEndian.Uint64(millis[:])))
	return at.After(now.Add(-intentWindow)) && at.Before(now.Add(intentWindow))
}

// cleanText reports UTF-8 of minimum to most bytes without NUL, control,
// format or line separator characters (Postgres TEXT refuses NUL; logs and
// consoles would show the rest, a bidi override spoofing a name, review
// b0b2 L4).
func cleanText(value string, minimum, most int) bool {
	if len(value) < minimum || len(value) > most || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

// Digest identifies an intent's content: the same ID sent again with
// another digest is a conflict.
func (intent Intent) Digest() [32]byte {
	hash := sha256.New()
	write := func(value string) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		hash.Write(size[:])
		hash.Write([]byte(value))
	}
	hash.Write(intent.ID[:])
	peer := intent.Peer.Bytes()
	hash.Write(peer[:])
	write(string(intent.Class))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(intent.Groups)))
	hash.Write(count[:])
	for _, value := range append(slices.Clone(intent.Groups), intent.Verb, intent.APIGroup, intent.Resource, intent.Subresource,
		intent.Namespace, intent.Name, intent.Impersonated, string(intent.TokenID)) {
		write(value)
	}
	var observed [8]byte
	binary.BigEndian.PutUint64(observed[:], uint64(intent.ObservedAt.UnixMilli()))
	hash.Write(observed[:])
	return [32]byte(hash.Sum(nil))
}

// Gateway names the gateway a session proved: its machine key fingerprint
// and node key, and the Workspace its intents queue under.
type Gateway struct {
	MachineFingerprint [32]byte
	NodeKey            [32]byte
	Workspace          string
}

// Owner is who a peer belongs to, as the gateway's map names it.
type Owner struct {
	Kind string // member, tags or workspace
	Ref  string
}

// Row is one intent ready to record: its gateway, owner, the map revision
// it was checked against; the store issues its audit_id.
type Row struct {
	Gateway         Gateway
	Intent          Intent
	Owner           Owner
	NetworkRevision int64
	ClockSkew       bool
	AuditID         publicid.ID
}

// Outcome is what Core answers for one intent (mtcp-v1 §6.10).
type Outcome string

// Outcomes; the first three come from the store, the rest from control.
const (
	OutcomeAccepted    Outcome = "accepted"
	OutcomeDuplicate   Outcome = "duplicate"
	OutcomeConflict    Outcome = "conflict"
	OutcomeInvalid     Outcome = "invalid"
	OutcomeGateway     Outcome = "gateway"
	OutcomeDevice      Outcome = "device"
	OutcomeNotGranted  Outcome = "not_granted"
	OutcomeStale       Outcome = "stale"
	OutcomeLimited     Outcome = "limited"
	OutcomeOverloaded  Outcome = "overloaded"
	OutcomeUnavailable Outcome = "unavailable"
)

// Recorded reports an outcome whose audit_id the gateway may forward with.
func (outcome Outcome) Recorded() bool {
	return outcome == OutcomeAccepted || outcome == OutcomeDuplicate
}

// Answer is one intent's answer: its audit_id when recorded, else when it
// may be sent again.
type Answer struct {
	Outcome    Outcome
	AuditID    publicid.ID
	RetryAfter time.Duration
}

// Finished is a forwarded operation's result, which the gateway reports
// after it (no answer, design §2 step 5).
type Finished struct {
	AuditID  publicid.ID
	Status   int
	Duration time.Duration
}

// DenialReason is why a gateway refused requests itself (type B).
type DenialReason string

// Denial reasons (mtcp-v1 §6.10).
const (
	DenialUnauthenticated DenialReason = "unauthenticated"
	DenialForbidden       DenialReason = "forbidden"
	DenialNotGranted      DenialReason = "not_granted"
	DenialStale           DenialReason = "stale"
	DenialLimited         DenialReason = "limited"
	DenialOther           DenialReason = "other"
)

// Denials counts a peer's refused requests of one reason over a span.
type Denials struct {
	Peer        publicid.ID // zero: not named
	Reason      DenialReason
	Count       int
	First, Last time.Time
}

// Reports are one gateway's finished operations and denials.
type Reports struct {
	Gateway  Gateway
	Finished []Finished
	Denials  []Denials
}
