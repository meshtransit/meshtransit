package mtrp

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/flynn/noise"

	"meshtransit.net/shared/key"
)

// Relay grant limits (mtrp-v1 §10).
const (
	// MaxGrantNetworks bounds the Networks one Private Interchange serves.
	MaxGrantNetworks = 1024
	// MaxGrantLifetime bounds how long a relay keeps using one grant.
	MaxGrantLifetime = time.Hour
	// maxSealedGrant bounds a sealed grant: e (32) + payload + tag (16).
	maxSealedGrant = 64 << 10
	grantPrologue  = "meshtransit/relay-grant/v1"
)

// ErrGrantSealed reports a sealed grant that is not for this relay or was
// altered.
var ErrGrantSealed = errors.New("mtrp: sealed relay grant not readable")

// RelayGrant tells a Private Interchange relay which Networks it serves.
// Core signs it as a DocumentRelayGrant and seals it to the relay's key, so
// only that relay learns its Networks. A relay with a grant accepts only
// sessions whose ticket names one of them, and routes only within them.
type RelayGrant struct {
	Relay     key.RelayPublic
	Sequence  uint64 // strictly increasing per relay
	IssuedAt  time.Time
	ExpiresAt time.Time
	Networks  [][16]byte // sorted, distinct; may be empty (serves nothing)
}

type relayGrantWire struct {
	Version     int             `json:"version"`
	Relay       key.RelayPublic `json:"relay"`
	Sequence    uint64          `json:"sequence"`
	IssuedAtMS  int64           `json:"issued_at_ms"`
	ExpiresAtMS int64           `json:"expires_at_ms"`
	Networks    []string        `json:"networks"` // UUIDs
}

// Payload validates g and encodes it as a signed-document payload.
func (g RelayGrant) Payload() ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	networks := make([]string, len(g.Networks))
	for i, network := range g.Networks {
		networks[i] = formatUUID(network)
	}
	return json.Marshal(relayGrantWire{
		Version: 1, Relay: g.Relay, Sequence: g.Sequence,
		IssuedAtMS: g.IssuedAt.UnixMilli(), ExpiresAtMS: g.ExpiresAt.UnixMilli(), Networks: networks,
	})
}

// ParseRelayGrant decodes a verified payload for relay; a grant for another
// relay, or one that expired before now, is rejected.
func ParseRelayGrant(payload []byte, relay key.RelayPublic, now time.Time) (RelayGrant, error) {
	var w relayGrantWire
	if err := json.Unmarshal(payload, &w); err != nil {
		return RelayGrant{}, fmt.Errorf("%w: %w", ErrDocumentMalformed, err)
	}
	if w.Version != 1 {
		return RelayGrant{}, fmt.Errorf("%w: relay grant version %d", ErrDocumentMalformed, w.Version)
	}
	if len(w.Networks) > MaxGrantNetworks {
		return RelayGrant{}, fmt.Errorf("%w: relay grant lists too many Networks", ErrDocumentMalformed)
	}
	g := RelayGrant{
		Relay: w.Relay, Sequence: w.Sequence, IssuedAt: time.UnixMilli(w.IssuedAtMS),
		ExpiresAt: time.UnixMilli(w.ExpiresAtMS),
	}
	for _, text := range w.Networks {
		network, ok := parseUUID(text)
		if !ok {
			return RelayGrant{}, fmt.Errorf("%w: relay grant Network %q", ErrDocumentMalformed, text)
		}
		g.Networks = append(g.Networks, network)
	}
	if err := g.validate(); err != nil {
		return RelayGrant{}, err
	}
	if g.Relay != relay {
		return RelayGrant{}, fmt.Errorf("%w: relay grant for another relay", ErrDocumentMalformed)
	}
	if !g.ExpiresAt.After(now) {
		return RelayGrant{}, fmt.Errorf("%w: relay grant expired", ErrDocumentMalformed)
	}
	return g, nil
}

// Serves reports whether the grant includes network.
func (g RelayGrant) Serves(network [16]byte) bool {
	_, found := slices.BinarySearchFunc(g.Networks, network, compareID)
	return found
}

func (g RelayGrant) validate() error {
	bad := func(reason string) error { return fmt.Errorf("%w: relay grant %s", ErrDocumentMalformed, reason) }
	switch {
	case g.Relay.IsZero():
		return bad("needs a relay key")
	case g.Sequence == 0:
		return bad("sequence must be positive")
	case !g.ExpiresAt.After(g.IssuedAt) || g.ExpiresAt.Sub(g.IssuedAt) > MaxGrantLifetime:
		return bad("lifetime out of range")
	case len(g.Networks) > MaxGrantNetworks:
		return bad("lists too many Networks")
	}
	for i, network := range g.Networks {
		if network == ([16]byte{}) || (i > 0 && compareID(g.Networks[i-1], network) >= 0) {
			return bad("Networks must be distinct, non-zero and sorted")
		}
	}
	return nil
}

func compareID(a, b [16]byte) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// SealRelayGrant encrypts a signed grant document to relay with the Noise N
// pattern (an ephemeral key and the relay's static key): only the relay can
// read it, and an attacker learns nothing about the Networks it serves.
func SealRelayGrant(document []byte, relay key.RelayPublic, random io.Reader) ([]byte, error) {
	if relay.IsZero() || len(document) == 0 || len(document) > maxSealedGrant-64 {
		return nil, ErrDocumentMalformed
	}
	if random == nil {
		random = rand.Reader
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Random: random, Pattern: noise.HandshakeN, Initiator: true,
		Prologue: []byte(grantPrologue), PeerStatic: append([]byte(nil), relay[:]...),
	})
	if err != nil {
		return nil, fmt.Errorf("mtrp: grant seal: %w", err)
	}
	sealed, _, _, err := hs.WriteMessage(nil, document)
	if err != nil {
		return nil, fmt.Errorf("mtrp: grant seal: %w", err)
	}
	return sealed, nil
}

// OpenRelayGrant decrypts a sealed grant with the relay's private key and
// returns the signed document inside; the caller verifies its signature.
func OpenRelayGrant(sealed []byte, relay key.RelayPrivate) ([]byte, error) {
	if relay.IsZero() || len(sealed) > maxSealedGrant {
		return nil, ErrGrantSealed
	}
	private := relay.ECDH().Bytes()
	defer clear(private)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeN, Initiator: false, Prologue: []byte(grantPrologue),
		StaticKeypair: noise.DHKey{Private: private, Public: relay.ECDH().PublicKey().Bytes()},
	})
	if err != nil {
		return nil, ErrGrantSealed
	}
	document, _, _, err := hs.ReadMessage(nil, sealed)
	if err != nil {
		return nil, ErrGrantSealed
	}
	return document, nil
}

const hexDigits = "0123456789abcdef"

// formatUUID writes id in the canonical 8-4-4-4-12 form.
func formatUUID(id [16]byte) string {
	out := make([]byte, 0, 36)
	for i, b := range id {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexDigits[b>>4], hexDigits[b&15])
	}
	return string(out)
}

// parseUUID reads the canonical lowercase form only.
func parseUUID(text string) ([16]byte, bool) {
	var id [16]byte
	if len(text) != 36 {
		return id, false
	}
	index := 0
	for i := 0; i < 36; {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if text[i] != '-' {
				return id, false
			}
			i++
			continue
		}
		high, okHigh := hexValue(text[i])
		low, okLow := hexValue(text[i+1])
		if !okHigh || !okLow {
			return id, false
		}
		id[index] = high<<4 | low
		index++
		i += 2
	}
	return id, true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}
