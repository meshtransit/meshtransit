package mtrp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// MaxGrantSize bounds an encoded InterchangeGrant: an MTT2 ticket's zone
// list (17 bytes × 10,001, base64) dominates.
const MaxGrantSize = 1 << 20

// InterchangeGrant is everything one node needs to use the Interchange: the
// Core keys that sign the relay map, the signed relay map, and the node's
// ticket. It reaches the node over its authenticated control session, so the
// signing keys need no further signature.
type InterchangeGrant struct {
	SigningKeys    []TrustedKey
	RelayMap       []byte // signed document (DocumentRelayMap)
	Ticket         []byte // signed ticket, opaque to the node
	TicketNotAfter time.Time
	// TicketZones is, for an MTT2 ticket, every zone it commits to
	// (EncodeZones); empty for MTT1.
	TicketZones []byte
	// FallbackTicket is, beside an MTT2 ticket, an MTT1 ticket for the same
	// keys naming its first MaxZones zones, for relays that do not take
	// MTT2 yet.
	FallbackTicket []byte
}

type grantWire struct {
	Version          int              `json:"version"`
	SigningKeys      []trustedKeyWire `json:"signing_keys"`
	RelayMap         []byte           `json:"relay_map"`
	Ticket           []byte           `json:"ticket"`
	TicketNotAfterMS int64            `json:"ticket_not_after_ms"`
	TicketZones      []byte           `json:"ticket_zones,omitempty"`    // version 2
	FallbackTicket   []byte           `json:"fallback_ticket,omitempty"` // version 2
}

// Marshal validates g and encodes it.
func (g InterchangeGrant) Marshal() ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	w := grantWire{
		Version: 1, RelayMap: g.RelayMap, Ticket: g.Ticket, TicketNotAfterMS: g.TicketNotAfter.UnixMilli(),
		TicketZones: g.TicketZones, FallbackTicket: g.FallbackTicket,
	}
	if len(g.TicketZones) != 0 {
		w.Version = 2
	}
	for _, k := range g.SigningKeys {
		w.SigningKeys = append(w.SigningKeys, trustedKeyWire{Key: k.Key, NotAfterMS: k.NotAfter.UnixMilli()})
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxGrantSize {
		return nil, fmt.Errorf("%w: grant too large", ErrDocumentMalformed)
	}
	return b, nil
}

// ParseInterchangeGrant decodes and validates a grant. The relay map is not
// verified here; use OpenRelayMap.
func ParseInterchangeGrant(b []byte) (InterchangeGrant, error) {
	if len(b) > MaxGrantSize {
		return InterchangeGrant{}, fmt.Errorf("%w: grant too large", ErrDocumentMalformed)
	}
	var w grantWire
	if err := json.Unmarshal(b, &w); err != nil {
		return InterchangeGrant{}, fmt.Errorf("%w: %w", ErrDocumentMalformed, err)
	}
	if w.Version != 1 && w.Version != 2 || (w.Version == 2) != (len(w.TicketZones) != 0) {
		return InterchangeGrant{}, fmt.Errorf("%w: grant version %d", ErrDocumentMalformed, w.Version)
	}
	g := InterchangeGrant{
		RelayMap: w.RelayMap, Ticket: w.Ticket, TicketNotAfter: time.UnixMilli(w.TicketNotAfterMS),
		TicketZones: w.TicketZones, FallbackTicket: w.FallbackTicket,
	}
	for _, k := range w.SigningKeys {
		g.SigningKeys = append(g.SigningKeys, TrustedKey{Key: k.Key, NotAfter: time.UnixMilli(k.NotAfterMS)})
	}
	if err := g.validate(); err != nil {
		return InterchangeGrant{}, err
	}
	return g, nil
}

func (g InterchangeGrant) validate() error {
	switch {
	case len(g.SigningKeys) == 0 || len(g.SigningKeys) > MaxTrustedSigningKeys:
		return fmt.Errorf("%w: 1..%d signing keys required", ErrDocumentMalformed, MaxTrustedSigningKeys)
	case len(g.RelayMap) == 0:
		return fmt.Errorf("%w: grant without relay map", ErrDocumentMalformed)
	case len(g.Ticket) == 0 || len(g.Ticket) > MaxTicketSize:
		return fmt.Errorf("%w: grant ticket size", ErrDocumentMalformed)
	case g.TicketNotAfter.UnixMilli() <= 0:
		return fmt.Errorf("%w: grant ticket expiry", ErrDocumentMalformed)
	}
	// The ticket is opaque to the grant, except that an MTT2 ticket needs the
	// zone list it commits to and only that list.
	if len(g.TicketZones) != 0 || bytes.HasPrefix(g.Ticket, []byte(ticketMagicV2)) {
		if _, err := CompleteTicket(g.Ticket, g.TicketZones); err != nil {
			return fmt.Errorf("%w: grant ticket zones", ErrDocumentMalformed)
		}
	}
	if len(g.FallbackTicket) != 0 {
		if err := CheckFallbackTicket(g.Ticket, g.FallbackTicket); err != nil {
			return fmt.Errorf("%w: grant fallback ticket", ErrDocumentMalformed)
		}
	}
	for i, k := range g.SigningKeys {
		if k.Key.IsZero() || slices.ContainsFunc(g.SigningKeys[:i], func(o TrustedKey) bool { return o.Key == k.Key }) {
			return fmt.Errorf("%w: invalid or duplicate signing key", ErrDocumentMalformed)
		}
	}
	return nil
}

// OpenRelayMap verifies the relay map with the grant's keys still valid at
// now and parses it.
func (g InterchangeGrant) OpenRelayMap(now time.Time) (RelayMap, error) {
	keys := make(StaticKeys, len(g.SigningKeys))
	for _, k := range g.SigningKeys {
		if now.Before(k.NotAfter) {
			keys[k.Key.ID()] = k.Key
		}
	}
	payload, _, err := OpenDocument(g.RelayMap, DocumentRelayMap, keys)
	if err != nil {
		return RelayMap{}, err
	}
	return ParseRelayMap(payload, now)
}

// CompleteTicket parses a ticket without verifying its signature and, for
// MTT2, adds zones, the encoded list it commits to; zones must be empty for
// MTT1. Nodes use it to check what Core sent before handing it to relays.
func CompleteTicket(ticket, zones []byte) (Ticket, error) {
	t, err := ParseTicketUnverified(ticket)
	if err != nil {
		return Ticket{}, err
	}
	if !t.IsV2() {
		if len(zones) != 0 {
			return Ticket{}, ErrTicketMalformed
		}
		return t, nil
	}
	if len(zones) == 0 {
		return Ticket{}, ErrTicketMalformed
	}
	all, err := ParseZones(zones)
	if err != nil {
		return Ticket{}, err
	}
	return t.WithZones(all)
}

// CheckFallbackTicket checks, without signatures, that fallback is an MTT1
// ticket for the keys of the MTT2 ticket primary, carrying its inline zones.
func CheckFallbackTicket(primary, fallback []byte) error {
	main, err := ParseTicketUnverified(primary)
	if err != nil {
		return err
	}
	backup, err := ParseTicketUnverified(fallback)
	if err != nil {
		return err
	}
	if !main.IsV2() || backup.IsV2() || backup.Node != main.Node || backup.Disco != main.Disco ||
		backup.Deployment != main.Deployment || !slices.Equal(backup.Zones, main.Zones) {
		return ErrTicketMalformed
	}
	return nil
}
