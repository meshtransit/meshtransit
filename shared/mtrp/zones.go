package mtrp

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
)

// MaxControlZones bounds the zones of one ZONES frame: its plaintext is
// type, ticket ID, offset and count followed by the zones, within
// MaxControlPlaintext.
const MaxControlZones = (MaxControlPlaintext - 1 - 16 - 2 - 1) / zoneSize

const zonesDomain = "meshtransit/mtrp-zones/v1\x00"

// digestZones is the MTT2 commitment to a canonical zone list (§6.1),
// bound to the ticket ID so a list cannot be replayed under another ticket.
func digestZones(ticketID [16]byte, zones []Zone) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(zonesDomain))
	h.Write(ticketID[:])
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(zones)))) //nolint:gosec // callers bound len by MaxTicketZones
	for _, z := range zones {
		h.Write([]byte{byte(z.Kind)})
		h.Write(z.ID[:])
	}
	var digest [sha256.Size]byte
	h.Sum(digest[:0])
	return digest
}

// EncodeZones encodes zones as kind u8 || id bytes[16] each.
func EncodeZones(zones []Zone) []byte {
	b := make([]byte, 0, len(zones)*zoneSize)
	for _, z := range zones {
		b = append(b, byte(z.Kind))
		b = append(b, z.ID[:]...)
	}
	return b
}

// ParseZones decodes EncodeZones output that is a valid canonical list of
// 1..MaxTicketZones zones.
func ParseZones(b []byte) ([]Zone, error) {
	if len(b) == 0 || len(b)%zoneSize != 0 || len(b)/zoneSize > MaxTicketZones {
		return nil, ErrTicketMalformed
	}
	zones := make([]Zone, len(b)/zoneSize)
	for i := range zones {
		zones[i].Kind = ZoneKind(b[i*zoneSize])
		copy(zones[i].ID[:], b[i*zoneSize+1:(i+1)*zoneSize])
	}
	if !canonicalZones(zones) {
		return nil, ErrTicketMalformed
	}
	return zones, nil
}

// ZoneFrames splits the zones of a complete MTT2 ticket that it does not
// carry inline into ZONES messages for the relay (§5.4). It returns nil for
// an MTT1 ticket.
func ZoneFrames(t Ticket) []ControlMessage {
	if !t.IsV2() || !t.ZonesComplete() {
		return nil
	}
	var frames []ControlMessage
	for offset := min(t.ZoneTotal, MaxZones); offset < t.ZoneTotal; offset += MaxControlZones {
		end := min(offset+MaxControlZones, t.ZoneTotal)
		frames = append(frames, ControlMessage{
			Type: ControlZones, TicketID: t.ID, ZoneOffset: uint16(offset), //nolint:gosec // offset < MaxTicketZones
			Zones: t.Zones[offset:end],
		})
	}
	return frames
}

// ZoneAssembly collects the zones of an MTT2 ticket from ZONES frames.
// The zones are trusted only once Complete has checked them against the
// ticket's signed digest.
type ZoneAssembly struct {
	ticket  Ticket
	zones   []Zone
	present []bool
	missing int
}

// NewZoneAssembly starts collecting the zones of a verified MTT2 ticket
// whose zones are not all inline.
func NewZoneAssembly(t Ticket) (*ZoneAssembly, bool) {
	if !t.IsV2() || t.ZonesComplete() {
		return nil, false
	}
	a := &ZoneAssembly{ticket: t, zones: make([]Zone, t.ZoneTotal), present: make([]bool, t.ZoneTotal)}
	copy(a.zones, t.Zones)
	for i := range t.Zones {
		a.present[i] = true
	}
	a.missing = t.ZoneTotal - len(t.Zones)
	return a, true
}

// Ticket returns the ticket being completed (with its inline zones only).
func (a *ZoneAssembly) Ticket() Ticket { return a.ticket }

// Add records a ZONES frame for this ticket. It reports false for a frame
// for another ticket or outside the list; the inline zones cannot be
// replaced. Repeated frames are harmless.
func (a *ZoneAssembly) Add(m ControlMessage) bool {
	offset := int(m.ZoneOffset)
	if m.Type != ControlZones || m.TicketID != a.ticket.ID || offset < len(a.ticket.Zones) ||
		len(m.Zones) == 0 || offset+len(m.Zones) > a.ticket.ZoneTotal {
		return false
	}
	for i, z := range m.Zones {
		if !a.present[offset+i] {
			a.present[offset+i] = true
			a.missing--
		}
		a.zones[offset+i] = z
	}
	return true
}

// Missing returns how many zones have not arrived.
func (a *ZoneAssembly) Missing() int { return a.missing }

// Complete returns the ticket with all its zones once every zone arrived
// and they match the digest. A mismatch (a frame altered or for an older
// list) discards everything received, so the node's next pass starts clean.
func (a *ZoneAssembly) Complete() (Ticket, bool) {
	if a.missing != 0 {
		return Ticket{}, false
	}
	complete, err := a.ticket.WithZones(a.zones)
	if err != nil {
		clear(a.present[len(a.ticket.Zones):])
		a.missing = a.ticket.ZoneTotal - len(a.ticket.Zones)
		return Ticket{}, false
	}
	a.zones = slices.Clip(a.zones)
	return complete, true
}
