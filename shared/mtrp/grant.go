package mtrp

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// InterchangeCapability names the grant in the legacy TS2021 map: Core puts
// it on the node's own map entry until MTCP carries KeyUpdate, the relay map
// and RelayTicket (mtcp-v1 §7.3, §9, §11).
const InterchangeCapability = "https://meshtransit.io/cap/interchange-v1"

// MaxGrantSize bounds an encoded InterchangeGrant.
const MaxGrantSize = 256 << 10

// InterchangeGrant is everything one node needs to use the Interchange: the
// Core keys that sign the relay map, the signed relay map, and the node's
// ticket. It reaches the node over its authenticated control session, so the
// signing keys need no further signature.
type InterchangeGrant struct {
	SigningKeys    []TrustedKey
	RelayMap       []byte // signed document (DocumentRelayMap)
	Ticket         []byte // signed ticket, opaque to the node
	TicketNotAfter time.Time
}

type grantWire struct {
	Version          int              `json:"version"`
	SigningKeys      []trustedKeyWire `json:"signing_keys"`
	RelayMap         []byte           `json:"relay_map"`
	Ticket           []byte           `json:"ticket"`
	TicketNotAfterMS int64            `json:"ticket_not_after_ms"`
}

// Marshal validates g and encodes it.
func (g InterchangeGrant) Marshal() ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	w := grantWire{Version: 1, RelayMap: g.RelayMap, Ticket: g.Ticket, TicketNotAfterMS: g.TicketNotAfter.UnixMilli()}
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
	if w.Version != 1 {
		return InterchangeGrant{}, fmt.Errorf("%w: grant version %d", ErrDocumentMalformed, w.Version)
	}
	g := InterchangeGrant{RelayMap: w.RelayMap, Ticket: w.Ticket, TicketNotAfter: time.UnixMilli(w.TicketNotAfterMS)}
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
