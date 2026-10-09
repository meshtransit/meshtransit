package mtrp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/blake2s"

	"meshtransit.net/shared/key"
)

// Relay state limits (mtrp-v1 §9).
const (
	// MaxRelayStateLifetime bounds expires_at - issued_at: a relay that stops
	// receiving updates notices within this time.
	MaxRelayStateLifetime = time.Hour
	// MaxTrustedSigningKeys bounds the signing keys a relay trusts at once
	// (current and next, with room for an emergency key).
	MaxTrustedSigningKeys = 4
	// MaxRevocations bounds the entries of one relay state.
	MaxRevocations = 1 << 20

	revocationDomain = "meshtransit/relay-revocation/v1\x00"
)

// RevocationKind says what a revocation entry hashes.
type RevocationKind uint8

// Revocation kinds.
const (
	RevokeTicket RevocationKind = 1 // ticket_id
	RevokeNode   RevocationKind = 2 // node public key
	RevokeDisco  RevocationKind = 3 // disco public key
)

// RevocationID is the published form of a revoked value: the first 16 bytes
// of BLAKE2s-256("meshtransit/relay-revocation/v1" || 0x00 || kind || value).
// Relays match tickets against it without the state listing keys.
type RevocationID [16]byte

// RevocationHash computes the RevocationID of a value.
func RevocationHash(kind RevocationKind, value []byte) RevocationID {
	h, _ := blake2s.New256(nil) // unkeyed BLAKE2s never fails
	h.Write([]byte(revocationDomain))
	h.Write([]byte{byte(kind)})
	h.Write(value)
	var id RevocationID
	copy(id[:], h.Sum(nil))
	return id
}

// TrustedKey is a Core signing key a relay accepts until NotAfter.
type TrustedKey struct {
	Key      key.SigningPublic
	NotAfter time.Time
}

// RelayState is the Core-signed document relays poll for trusted signing
// keys, revocations and drain commands (mtrp-v1 §9).
type RelayState struct {
	Sequence    int64 // strictly increasing; relays ignore older states
	IssuedAt    time.Time
	ExpiresAt   time.Time
	SigningKeys []TrustedKey
	Tickets     []RevocationID
	Nodes       []RevocationID
	Discos      []RevocationID
	Drain       []key.RelayPublic
}

type relayStateWire struct {
	Version     int               `json:"version"`
	Sequence    int64             `json:"sequence"`
	IssuedAtMS  int64             `json:"issued_at_ms"`
	ExpiresAtMS int64             `json:"expires_at_ms"`
	SigningKeys []trustedKeyWire  `json:"signing_keys"`
	Revoked     revokedWire       `json:"revoked"`
	Drain       []key.RelayPublic `json:"drain"`
}

type trustedKeyWire struct {
	Key        key.SigningPublic `json:"key"`
	NotAfterMS int64             `json:"not_after_ms"`
}

type revokedWire struct {
	Tickets []string `json:"tickets"`
	Nodes   []string `json:"nodes"`
	Discos  []string `json:"discos"`
}

// Payload validates s and encodes it as a signed-document payload.
func (s RelayState) Payload() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	w := relayStateWire{
		Version: 1, Sequence: s.Sequence,
		IssuedAtMS: s.IssuedAt.UnixMilli(), ExpiresAtMS: s.ExpiresAt.UnixMilli(),
		Revoked: revokedWire{Tickets: hexIDs(s.Tickets), Nodes: hexIDs(s.Nodes), Discos: hexIDs(s.Discos)},
		Drain:   s.Drain,
	}
	if w.Drain == nil {
		w.Drain = []key.RelayPublic{}
	}
	for _, k := range s.SigningKeys {
		w.SigningKeys = append(w.SigningKeys, trustedKeyWire{Key: k.Key, NotAfterMS: k.NotAfter.UnixMilli()})
	}
	return json.Marshal(w)
}

// ParseRelayState decodes and validates a verified payload. It does not
// check freshness; callers compare ExpiresAt and Sequence with their state.
func ParseRelayState(payload []byte) (RelayState, error) {
	var w relayStateWire
	if err := json.Unmarshal(payload, &w); err != nil {
		return RelayState{}, fmt.Errorf("%w: %w", ErrDocumentMalformed, err)
	}
	if w.Version != 1 {
		return RelayState{}, fmt.Errorf("%w: relay state version %d", ErrDocumentMalformed, w.Version)
	}
	s := RelayState{
		Sequence: w.Sequence, IssuedAt: time.UnixMilli(w.IssuedAtMS), ExpiresAt: time.UnixMilli(w.ExpiresAtMS),
		Drain: w.Drain,
	}
	for _, k := range w.SigningKeys {
		s.SigningKeys = append(s.SigningKeys, TrustedKey{Key: k.Key, NotAfter: time.UnixMilli(k.NotAfterMS)})
	}
	var err error
	if s.Tickets, err = parseIDs(w.Revoked.Tickets); err != nil {
		return RelayState{}, err
	}
	if s.Nodes, err = parseIDs(w.Revoked.Nodes); err != nil {
		return RelayState{}, err
	}
	if s.Discos, err = parseIDs(w.Revoked.Discos); err != nil {
		return RelayState{}, err
	}
	if err := s.validate(); err != nil {
		return RelayState{}, err
	}
	return s, nil
}

func (s RelayState) validate() error {
	switch {
	case s.Sequence <= 0:
		return fmt.Errorf("%w: sequence must be positive", ErrDocumentMalformed)
	case !s.ExpiresAt.After(s.IssuedAt) || s.ExpiresAt.Sub(s.IssuedAt) > MaxRelayStateLifetime:
		return fmt.Errorf("%w: relay state lifetime out of range", ErrDocumentMalformed)
	case len(s.SigningKeys) == 0 || len(s.SigningKeys) > MaxTrustedSigningKeys:
		return fmt.Errorf("%w: 1..%d signing keys required", ErrDocumentMalformed, MaxTrustedSigningKeys)
	case len(s.Tickets)+len(s.Nodes)+len(s.Discos) > MaxRevocations:
		return fmt.Errorf("%w: too many revocations", ErrDocumentMalformed)
	case len(s.Drain) > 1024:
		return fmt.Errorf("%w: too many drain entries", ErrDocumentMalformed)
	}
	for i, k := range s.SigningKeys {
		if k.Key.IsZero() || slices.ContainsFunc(s.SigningKeys[:i], func(o TrustedKey) bool { return o.Key == k.Key }) {
			return fmt.Errorf("%w: invalid or duplicate signing key", ErrDocumentMalformed)
		}
	}
	for _, r := range s.Drain {
		if r.IsZero() {
			return fmt.Errorf("%w: invalid drain entry", ErrDocumentMalformed)
		}
	}
	return nil
}

func hexIDs(ids []RevocationID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = hex.EncodeToString(id[:])
	}
	return out
}

func parseIDs(in []string) ([]RevocationID, error) {
	if len(in) > MaxRevocations {
		return nil, fmt.Errorf("%w: too many revocations", ErrDocumentMalformed)
	}
	out := make([]RevocationID, len(in))
	for i, s := range in {
		if len(s) != 2*len(RevocationID{}) {
			return nil, fmt.Errorf("%w: revocation entry length", ErrDocumentMalformed)
		}
		if _, err := hex.Decode(out[i][:], []byte(s)); err != nil {
			return nil, fmt.Errorf("%w: revocation entry", ErrDocumentMalformed)
		}
	}
	return out, nil
}

// RevocationSet answers Revoked for a relay state. It is immutable and safe
// for concurrent use.
type RevocationSet struct {
	tickets, nodes, discos map[RevocationID]struct{}
}

// NewRevocationSet indexes a state's revocations.
func NewRevocationSet(s RelayState) *RevocationSet {
	index := func(ids []RevocationID) map[RevocationID]struct{} {
		m := make(map[RevocationID]struct{}, len(ids))
		for _, id := range ids {
			m[id] = struct{}{}
		}
		return m
	}
	return &RevocationSet{tickets: index(s.Tickets), nodes: index(s.Nodes), discos: index(s.Discos)}
}

// Revoked implements Revocations.
func (r *RevocationSet) Revoked(t Ticket) bool {
	if r == nil {
		return false
	}
	if _, ok := r.tickets[RevocationHash(RevokeTicket, t.ID[:])]; ok {
		return true
	}
	if _, ok := r.nodes[RevocationHash(RevokeNode, t.Node[:])]; ok {
		return true
	}
	_, ok := r.discos[RevocationHash(RevokeDisco, t.Disco[:])]
	return ok
}

// Len returns the number of entries.
func (r *RevocationSet) Len() int {
	if r == nil {
		return 0
	}
	return len(r.tickets) + len(r.nodes) + len(r.discos)
}

var errNoKeys = errors.New("mtrp: no trusted keys")

// TrustedKeySet returns the state's signing keys still valid at now, as a
// KeySet for verifying tickets and the next relay state.
func (s RelayState) TrustedKeySet(now time.Time) (StaticKeys, error) {
	keys := make(StaticKeys, len(s.SigningKeys))
	for _, k := range s.SigningKeys {
		if now.Before(k.NotAfter) {
			keys[k.Key.ID()] = k.Key
		}
	}
	if len(keys) == 0 {
		return nil, errNoKeys
	}
	return keys, nil
}
