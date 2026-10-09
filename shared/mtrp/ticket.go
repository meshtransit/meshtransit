package mtrp

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"meshtransit.net/shared/internal/wire"
	"meshtransit.net/shared/key"
)

// Ticket limits (mtrp-v1 §6).
const (
	// MaxTicketSize bounds an encoded ticket on the wire.
	MaxTicketSize = 1024
	// MaxZones bounds the zones of one ticket.
	MaxZones = 32
	// MaxTicketLifetime bounds not_after - issued_at.
	MaxTicketLifetime = 15 * time.Minute
	// MaxIssueSkew tolerates a relay clock behind Core's.
	MaxIssueSkew = time.Minute

	ticketMagic      = "MTT1"
	ticketDomain     = "meshtransit/mtrp-ticket/v1\x00"
	zoneSize         = 1 + 16
	ticketFixedSize  = 4 + key.KeyIDSize + 16 + 8 + 8 + key.Size + key.Size + 16 + 4 + 2 + 1
	ticketSignedSize = ed25519.SignatureSize
)

var (
	// ErrTicketMalformed reports a ticket that is not canonical.
	ErrTicketMalformed = errors.New("mtrp: malformed ticket")
	// ErrTicketUnknownKey reports a ticket signed by an untrusted key ID.
	ErrTicketUnknownKey = errors.New("mtrp: ticket signed by unknown key")
	// ErrTicketSignature reports an invalid signature.
	ErrTicketSignature = errors.New("mtrp: invalid ticket signature")
	// ErrTicketTime reports a ticket outside its validity window or lifetime bound.
	ErrTicketTime = errors.New("mtrp: ticket not valid at this time")
	// ErrTicketRevoked reports a revoked ticket, node or disco key.
	ErrTicketRevoked = errors.New("mtrp: ticket revoked")
)

// ZoneKind classifies a zone.
type ZoneKind uint8

// Zone kinds.
const (
	ZoneNetwork       ZoneKind = 1
	ZoneTrustContract ZoneKind = 2
)

// Zone is an authorisation scope: two sessions may exchange traffic only if
// their tickets share a zone.
type Zone struct {
	Kind ZoneKind
	ID   [16]byte
}

func compareZones(a, b Zone) int {
	if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	return bytes.Compare(a.ID[:], b.ID[:])
}

// Ticket is a Core-issued relay authorisation.
type Ticket struct {
	KeyID      key.KeyID
	ID         [16]byte
	IssuedAtMS int64
	NotAfterMS int64
	Node       key.NodePublic
	Disco      key.DiscoPublic
	Deployment [16]byte
	MaxBPS     uint32
	MaxRoutes  uint16
	Zones      []Zone // sorted by (Kind, ID), no duplicates
}

// NotAfter returns the expiry as a time.
func (t Ticket) NotAfter() time.Time { return time.UnixMilli(t.NotAfterMS) }

// Sign validates t, sorts a copy of its zones into canonical order and
// returns the signed encoding. KeyID is taken from signer.
func (t Ticket) Sign(signer key.SigningPrivate) ([]byte, error) {
	if signer.IsZero() {
		return nil, key.ErrInvalid
	}
	t.KeyID = signer.Public().ID()
	t.Zones = slices.SortedFunc(slices.Values(t.Zones), compareZones)
	body, err := t.appendBody(make([]byte, 0, ticketFixedSize+len(t.Zones)*zoneSize+ticketSignedSize))
	if err != nil {
		return nil, err
	}
	return append(body, signer.Sign(signingInput(body))...), nil
}

func (t Ticket) validFields() bool {
	if t.ID == ([16]byte{}) || t.Node.IsZero() || t.Disco.IsZero() || t.Deployment == ([16]byte{}) {
		return false
	}
	if t.IssuedAtMS <= 0 || t.NotAfterMS <= t.IssuedAtMS ||
		time.Duration(t.NotAfterMS-t.IssuedAtMS)*time.Millisecond > MaxTicketLifetime {
		return false
	}
	if len(t.Zones) == 0 || len(t.Zones) > MaxZones {
		return false
	}
	for i, z := range t.Zones {
		if (z.Kind != ZoneNetwork && z.Kind != ZoneTrustContract) || z.ID == ([16]byte{}) {
			return false
		}
		if i > 0 && compareZones(t.Zones[i-1], z) >= 0 { // canonical: strictly increasing
			return false
		}
	}
	return true
}

func (t Ticket) appendBody(dst []byte) ([]byte, error) {
	if !t.validFields() {
		return nil, ErrTicketMalformed
	}
	dst = append(dst, ticketMagic...)
	dst = append(dst, t.KeyID[:]...)
	dst = append(dst, t.ID[:]...)
	var issuedOK, notAfterOK bool
	dst, issuedOK = wire.AppendMillis(dst, t.IssuedAtMS)
	dst, notAfterOK = wire.AppendMillis(dst, t.NotAfterMS)
	if !issuedOK || !notAfterOK {
		return nil, ErrTicketMalformed
	}
	dst = append(dst, t.Node[:]...)
	dst = append(dst, t.Disco[:]...)
	dst = append(dst, t.Deployment[:]...)
	dst = binary.BigEndian.AppendUint32(dst, t.MaxBPS)
	dst = binary.BigEndian.AppendUint16(dst, t.MaxRoutes)
	zoneCount, ok := wire.Len8(len(t.Zones))
	if !ok {
		return nil, ErrTicketMalformed
	}
	dst = append(dst, zoneCount)
	for _, z := range t.Zones {
		dst = append(dst, byte(z.Kind))
		dst = append(dst, z.ID[:]...)
	}
	return dst, nil
}

func signingInput(body []byte) []byte {
	in := make([]byte, 0, len(ticketDomain)+len(body))
	return append(append(in, ticketDomain...), body...)
}

// parseTicket decodes a ticket and returns its signed body and signature.
func parseTicket(b []byte) (Ticket, []byte, []byte, error) {
	if len(b) < ticketFixedSize+zoneSize+ticketSignedSize || len(b) > MaxTicketSize || string(b[:4]) != ticketMagic {
		return Ticket{}, nil, nil, ErrTicketMalformed
	}
	var t Ticket
	r := b[4:]
	next := func(n int) []byte { v := r[:n]; r = r[n:]; return v }
	copy(t.KeyID[:], next(key.KeyIDSize))
	copy(t.ID[:], next(16))
	issued, issuedOK := wire.Millis(next(8))
	notAfter, notAfterOK := wire.Millis(next(8))
	if !issuedOK || !notAfterOK {
		return Ticket{}, nil, nil, ErrTicketMalformed
	}
	t.IssuedAtMS, t.NotAfterMS = issued, notAfter
	copy(t.Node[:], next(key.Size))
	copy(t.Disco[:], next(key.Size))
	copy(t.Deployment[:], next(16))
	t.MaxBPS = binary.BigEndian.Uint32(next(4))
	t.MaxRoutes = binary.BigEndian.Uint16(next(2))
	count := int(next(1)[0])
	if count == 0 || count > MaxZones || len(r) != count*zoneSize+ticketSignedSize {
		return Ticket{}, nil, nil, ErrTicketMalformed
	}
	t.Zones = make([]Zone, count)
	for i := range t.Zones {
		t.Zones[i].Kind = ZoneKind(next(1)[0])
		copy(t.Zones[i].ID[:], next(16))
	}
	if !t.validFields() {
		return Ticket{}, nil, nil, ErrTicketMalformed
	}
	split := len(b) - ticketSignedSize
	return t, b[:split], b[split:], nil
}

// KeySet resolves the Core signing keys a relay currently trusts.
type KeySet interface {
	SigningKey(id key.KeyID) (key.SigningPublic, bool)
}

// StaticKeys is a fixed KeySet, keyed by key ID.
type StaticKeys map[key.KeyID]key.SigningPublic

// SigningKey implements KeySet.
func (s StaticKeys) SigningKey(id key.KeyID) (key.SigningPublic, bool) {
	k, ok := s[id]
	return k, ok
}

// NewStaticKeys builds a StaticKeys from public keys.
func NewStaticKeys(keys ...key.SigningPublic) StaticKeys {
	s := make(StaticKeys, len(keys))
	for _, k := range keys {
		s[k.ID()] = k
	}
	return s
}

// Revocations reports revoked tickets, nodes and disco keys.
type Revocations interface {
	Revoked(t Ticket) bool
}

// Verifier checks tickets against trusted keys, time and revocations.
type Verifier struct {
	Keys        KeySet
	Revocations Revocations      // optional
	Now         func() time.Time // nil means time.Now
}

// Verify parses and checks a ticket in the order the spec requires. It
// returns the ticket only if every check passes.
func (v Verifier) Verify(b []byte) (Ticket, error) {
	t, body, signature, err := parseTicket(b)
	if err != nil {
		return Ticket{}, err
	}
	if v.Keys == nil {
		return Ticket{}, ErrTicketUnknownKey
	}
	public, ok := v.Keys.SigningKey(t.KeyID)
	if !ok || public.ID() != t.KeyID {
		return Ticket{}, ErrTicketUnknownKey
	}
	if !public.Verify(signingInput(body), signature) {
		return Ticket{}, ErrTicketSignature
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	nowMS := now.UnixMilli()
	if nowMS < t.IssuedAtMS-MaxIssueSkew.Milliseconds() || nowMS >= t.NotAfterMS {
		return Ticket{}, ErrTicketTime
	}
	if v.Revocations != nil && v.Revocations.Revoked(t) {
		return Ticket{}, ErrTicketRevoked
	}
	return t, nil
}

// SharesZone reports whether two tickets share a zone. Zones are canonical
// (sorted, unique), so a merge walk is linear.
func SharesZone(a, b Ticket) bool {
	i, j := 0, 0
	for i < len(a.Zones) && j < len(b.Zones) {
		switch c := compareZones(a.Zones[i], b.Zones[j]); {
		case c == 0:
			return true
		case c < 0:
			i++
		default:
			j++
		}
	}
	return false
}
