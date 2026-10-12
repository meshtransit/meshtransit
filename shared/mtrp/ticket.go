package mtrp

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/sha256"
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
	// MaxZones bounds the zones of one MTT1 ticket, and the zones an MTT2
	// ticket carries inline.
	MaxZones = 32
	// MaxTicketZones bounds the zones an MTT2 ticket commits to (§6.1).
	MaxTicketZones = 16384
	// MaxTicketLifetime bounds not_after - issued_at.
	MaxTicketLifetime = 15 * time.Minute
	// MaxIssueSkew tolerates a relay clock behind Core's.
	MaxIssueSkew = time.Minute

	ticketMagic      = "MTT1"
	ticketMagicV2    = "MTT2"
	ticketDomain     = "meshtransit/mtrp-ticket/v1\x00"
	zoneSize         = 1 + 16
	ticketFixedSize  = 4 + key.KeyIDSize + 16 + 8 + 8 + key.Size + key.Size + 16 + 4 + 2 + 1
	ticketV2Size     = ticketFixedSize - 1 + 2 + sha256.Size + 1
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

// CompareZones orders zones canonically: by kind, then ID.
func CompareZones(a, b Zone) int { return compareZones(a, b) }

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
	// An MTT2 ticket (§6.1) commits to ZoneTotal zones by ZoneDigest and
	// carries only the first min(ZoneTotal, MaxZones) in Zones until the
	// rest are added with WithZones. Both are zero for MTT1.
	ZoneTotal  int
	ZoneDigest [sha256.Size]byte
}

// IsV2 reports whether t is an MTT2 ticket.
func (t Ticket) IsV2() bool { return t.ZoneTotal != 0 }

// ZonesComplete reports whether Zones holds every zone the ticket grants.
func (t Ticket) ZonesComplete() bool { return !t.IsV2() || len(t.Zones) == t.ZoneTotal }

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
	t.ZoneTotal, t.ZoneDigest = 0, [sha256.Size]byte{} // MTT1
	body, err := t.appendBody(make([]byte, 0, ticketFixedSize+len(t.Zones)*zoneSize+ticketSignedSize))
	if err != nil {
		return nil, err
	}
	return append(body, signer.Sign(signingInput(body))...), nil
}

// SignZones signs t as an MTT2 ticket (§6.1) granting every zone in
// t.Zones, which may hold up to MaxTicketZones. It returns the ticket, which
// carries the first MaxZones zones inline, and the canonical encoding of
// all zones (EncodeZones) that the node hands the relay in ZONES frames.
func (t Ticket) SignZones(signer key.SigningPrivate) (ticket, zones []byte, err error) {
	if signer.IsZero() {
		return nil, nil, key.ErrInvalid
	}
	all := slices.SortedFunc(slices.Values(t.Zones), compareZones)
	if len(all) == 0 || len(all) > MaxTicketZones || !canonicalZones(all) {
		return nil, nil, ErrTicketMalformed
	}
	t.KeyID = signer.Public().ID()
	t.ZoneTotal, t.ZoneDigest = len(all), digestZones(t.ID, all)
	t.Zones = all[:min(len(all), MaxZones)]
	body, err := t.appendBody(make([]byte, 0, ticketV2Size+len(t.Zones)*zoneSize+ticketSignedSize))
	if err != nil {
		return nil, nil, err
	}
	return append(body, signer.Sign(signingInput(body))...), EncodeZones(all), nil
}

// WithZones returns t granting all of zones, the complete canonical list an
// MTT2 ticket commits to: it must match ZoneTotal, ZoneDigest and the zones
// carried inline. An MTT1 ticket or a complete one is returned unchanged
// when zones equals its own.
func (t Ticket) WithZones(zones []Zone) (Ticket, error) {
	if !t.IsV2() {
		if slices.Equal(zones, t.Zones) {
			return t, nil
		}
		return Ticket{}, ErrTicketMalformed
	}
	if len(zones) != t.ZoneTotal || !canonicalZones(zones) ||
		!slices.Equal(zones[:min(len(zones), MaxZones)], t.Zones[:min(len(t.Zones), MaxZones)]) ||
		digestZones(t.ID, zones) != t.ZoneDigest {
		return Ticket{}, ErrTicketMalformed
	}
	t.Zones = slices.Clone(zones)
	return t, nil
}

// canonicalZones reports whether zones are valid and strictly increasing.
func canonicalZones(zones []Zone) bool {
	for i, z := range zones {
		if (z.Kind != ZoneNetwork && z.Kind != ZoneTrustContract) || z.ID == ([16]byte{}) {
			return false
		}
		if i > 0 && compareZones(zones[i-1], z) >= 0 { // canonical: strictly increasing
			return false
		}
	}
	return true
}

func (t Ticket) validFields() bool {
	if t.ID == ([16]byte{}) || t.Node.IsZero() || t.Disco.IsZero() || t.Deployment == ([16]byte{}) {
		return false
	}
	if t.IssuedAtMS <= 0 || t.NotAfterMS <= t.IssuedAtMS ||
		time.Duration(t.NotAfterMS-t.IssuedAtMS)*time.Millisecond > MaxTicketLifetime {
		return false
	}
	if t.IsV2() {
		// The inline zones are exactly the first min(total, MaxZones).
		if t.ZoneTotal < 0 || t.ZoneTotal > MaxTicketZones || len(t.Zones) != min(t.ZoneTotal, MaxZones) {
			return false
		}
	} else if len(t.Zones) == 0 || len(t.Zones) > MaxZones {
		return false
	}
	return canonicalZones(t.Zones)
}

func (t Ticket) appendBody(dst []byte) ([]byte, error) {
	if !t.validFields() {
		return nil, ErrTicketMalformed
	}
	if t.IsV2() {
		dst = append(dst, ticketMagicV2...)
	} else {
		dst = append(dst, ticketMagic...)
	}
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
	if t.IsV2() {
		total, ok := wire.Len16(t.ZoneTotal)
		if !ok {
			return nil, ErrTicketMalformed
		}
		dst = binary.BigEndian.AppendUint16(dst, total)
		dst = append(dst, t.ZoneDigest[:]...)
	}
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

// ParseTicketUnverified decodes a ticket without checking its signature or
// validity window. Nodes use it to learn which disco key and expiry the
// ticket they were given carries; only relays verify tickets.
func ParseTicketUnverified(b []byte) (Ticket, error) {
	t, _, _, err := parseTicket(b)
	return t, err
}

// parseTicket decodes a ticket and returns its signed body and signature.
func parseTicket(b []byte) (Ticket, []byte, []byte, error) {
	if len(b) < ticketFixedSize+zoneSize+ticketSignedSize || len(b) > MaxTicketSize ||
		string(b[:4]) != ticketMagic && string(b[:4]) != ticketMagicV2 {
		return Ticket{}, nil, nil, ErrTicketMalformed
	}
	v2 := string(b[:4]) == ticketMagicV2
	if v2 && len(b) < ticketV2Size+zoneSize+ticketSignedSize {
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
	if v2 {
		t.ZoneTotal = int(binary.BigEndian.Uint16(next(2)))
		copy(t.ZoneDigest[:], next(sha256.Size))
		if t.ZoneTotal == 0 {
			return Ticket{}, nil, nil, ErrTicketMalformed
		}
	}
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

// ZoneRevocations is implemented by revocation sources that also withdraw
// zones (mtrp-v1 §9).
type ZoneRevocations interface {
	ZoneRevoked(z Zone) bool
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
	if IsRevoked(t, v.Revocations) {
		return Ticket{}, ErrTicketRevoked
	}
	return t, nil
}

// IsRevoked reports whether r revokes t: its ID, node or disco key is
// listed, or every one of its zones is withdrawn so it can reach no one.
// r may be nil.
func IsRevoked(t Ticket, r Revocations) bool {
	if r == nil {
		return false
	}
	if r.Revoked(t) {
		return true
	}
	// For an MTT2 ticket still missing zones this judges the inline ones,
	// which include its Network zone: one whose Network zone is withdrawn
	// (a Private Interchange relay not serving its Network) is refused at
	// once, while a withdrawn inline contract cannot revoke it alone.
	zones, ok := r.(ZoneRevocations)
	return ok && len(t.Zones) != 0 && !slices.ContainsFunc(t.Zones, func(z Zone) bool { return !zones.ZoneRevoked(z) })
}

// SharesZone reports whether two tickets share a zone. Zones are canonical
// (sorted, unique), so a merge walk is linear.
func SharesZone(a, b Ticket) bool { return SharesLiveZone(a, b, nil) }

// SharesLiveZone reports whether two tickets share a zone that r has not
// withdrawn. r may be nil or not implement ZoneRevocations.
func SharesLiveZone(a, b Ticket, r Revocations) bool {
	_, ok := SharedLiveZone(a, b, r)
	return ok
}

// SharedLiveZone returns the first zone (in canonical order) that both
// tickets carry and r has not withdrawn. It costs O(len(a)+len(b)), or
// O(small × log large) when one side is much smaller, so a node with few
// zones stays cheap against one with thousands.
func SharedLiveZone(a, b Ticket, r Revocations) (Zone, bool) {
	zones, _ := r.(ZoneRevocations)
	live := func(z Zone) bool { return zones == nil || !zones.ZoneRevoked(z) }
	small, large := a.Zones, b.Zones
	if len(small) > len(large) {
		small, large = large, small
	}
	if len(small)*16 < len(large) {
		for _, z := range small {
			if _, found := slices.BinarySearchFunc(large, z, compareZones); found && live(z) {
				return z, true
			}
		}
		return Zone{}, false
	}
	i, j := 0, 0
	for i < len(a.Zones) && j < len(b.Zones) {
		switch c := compareZones(a.Zones[i], b.Zones[j]); {
		case c == 0:
			if live(a.Zones[i]) {
				return a.Zones[i], true
			}
			i++
			j++
		case c < 0:
			i++
		default:
			j++
		}
	}
	return Zone{}, false
}

// HasLiveZone reports whether t carries z and r has not withdrawn it.
func HasLiveZone(t Ticket, z Zone, r Revocations) bool {
	if _, found := slices.BinarySearchFunc(t.Zones, z, compareZones); !found {
		return false
	}
	zones, ok := r.(ZoneRevocations)
	return !ok || !zones.ZoneRevoked(z)
}
