// Package policydigest computes the policy digest v1 of a packet filter
// (docs/protocol/policy-digest-v1.md): one SHA-256 value that Core computes
// over the filter it sends a node and the node computes over the filter it
// actually enforces, so the two can be compared.
//
// The digest is semantic: it expands every rule into single (protocol,
// source, destination, ports) grants and hashes their sorted, de-duplicated
// set. How rules are grouped, split or ordered does not change it.
//
// The package is pure computation; it performs no I/O.
package policydigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// Version is the digest version this package computes.
const Version = 1

// MaximumGrants bounds the expanded grant set, so a hostile or corrupt filter
// cannot make a digest arbitrarily expensive.
const MaximumGrants = 1 << 20

// MaximumCapabilityLength bounds one capability selector.
const MaximumCapabilityLength = 1024

const (
	domainSeparator = "meshtransit policy digest v1\x00"
	textPrefix      = "sha256:"
	// defaultProtocols stands for an empty protocol list, which means TCP,
	// UDP and ICMP; it is outside the 8-bit protocol number space.
	defaultProtocols = 0x0100
)

var (
	// ErrInvalidRule reports a selector or destination the digest cannot
	// represent.
	ErrInvalidRule = errors.New("policydigest: invalid rule")
	// ErrTooLarge reports a filter that expands beyond MaximumGrants.
	ErrTooLarge = errors.New("policydigest: filter too large")
	// ErrInvalidDigest reports malformed digest text.
	ErrInvalidDigest = errors.New("policydigest: invalid digest")
)

// Kind identifies one selector representation.
type Kind uint8

// Selector kinds, numbered as they are encoded.
const (
	KindAny        Kind = 1
	KindPrefix     Kind = 2
	KindRange      Kind = 3
	KindCapability Kind = 4
)

// Selector is an address wildcard, prefix, inclusive range or capability.
type Selector struct {
	Kind       Kind
	Prefix     netip.Prefix
	RangeStart netip.Addr
	RangeEnd   netip.Addr
	Capability string
}

// Destination is a selector with an inclusive port range.
type Destination struct {
	Selector Selector
	PortFrom uint16
	PortTo   uint16
}

// Rule is one allow rule. An empty Protocols list means TCP, UDP and ICMP.
// A rule without destinations grants nothing and does not count.
type Rule struct {
	Sources      []Selector
	Destinations []Destination
	Protocols    []uint8
}

// Digest is a policy digest v1 value.
type Digest [sha256.Size]byte

// IsZero reports the zero value, which no filter produces.
func (digest Digest) IsZero() bool { return digest == Digest{} }

// String returns "sha256:" followed by lowercase hex.
func (digest Digest) String() string { return textPrefix + hex.EncodeToString(digest[:]) }

// MarshalText implements encoding.TextMarshaler.
func (digest Digest) MarshalText() ([]byte, error) { return []byte(digest.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (digest *Digest) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*digest = parsed
	return nil
}

// Parse reads the text form produced by String. It accepts only that exact,
// lowercase form.
func Parse(text string) (Digest, error) {
	encoded, found := strings.CutPrefix(text, textPrefix)
	if !found || len(encoded) != hex.EncodedLen(sha256.Size) || strings.ToLower(encoded) != encoded {
		return Digest{}, ErrInvalidDigest
	}
	var digest Digest
	if _, err := hex.Decode(digest[:], []byte(encoded)); err != nil || digest.IsZero() {
		return Digest{}, ErrInvalidDigest
	}
	return digest, nil
}

// Compute returns the digest of rules and how many distinct grants it covers.
func Compute(rules []Rule) (Digest, int, error) {
	grants := make([][]byte, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Destinations) == 0 {
			continue
		}
		protocols := protocolTokens(rule.Protocols)
		count := len(protocols) * len(rule.Sources) * len(rule.Destinations)
		if count > MaximumGrants || len(grants)+count > MaximumGrants {
			return Digest{}, 0, ErrTooLarge
		}
		sources := make([][]byte, len(rule.Sources))
		for index, source := range rule.Sources {
			encoded, err := appendSelector(nil, source)
			if err != nil {
				return Digest{}, 0, err
			}
			sources[index] = encoded
		}
		for _, destination := range rule.Destinations {
			if destination.PortFrom > destination.PortTo {
				return Digest{}, 0, ErrInvalidRule
			}
			target, err := appendSelector(nil, destination.Selector)
			if err != nil {
				return Digest{}, 0, err
			}
			for _, protocol := range protocols {
				for _, source := range sources {
					grants = append(grants, encodeGrant(protocol, source, target, destination))
				}
			}
		}
	}
	slices.SortFunc(grants, bytes.Compare)
	grants = slices.CompactFunc(grants, bytes.Equal)

	hash := sha256.New()
	hash.Write([]byte(domainSeparator))
	hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(grants))))
	for _, grant := range grants {
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(grant)))) //nolint:gosec // G115: a grant is a few dozen bytes
		hash.Write(grant)
	}
	var digest Digest
	hash.Sum(digest[:0])
	return digest, len(grants), nil
}

func protocolTokens(protocols []uint8) []uint16 {
	if len(protocols) == 0 {
		return []uint16{defaultProtocols}
	}
	tokens := make([]uint16, 0, len(protocols))
	for _, protocol := range protocols {
		if !slices.Contains(tokens, uint16(protocol)) {
			tokens = append(tokens, uint16(protocol))
		}
	}
	return tokens
}

// encodeGrant lays out protocol(2) source destination port_from(2) port_to(2);
// selectors are self-delimiting.
func encodeGrant(protocol uint16, source, target []byte, destination Destination) []byte {
	grant := make([]byte, 0, 6+len(source)+len(target))
	grant = binary.BigEndian.AppendUint16(grant, protocol)
	grant = append(grant, source...)
	grant = append(grant, target...)
	grant = binary.BigEndian.AppendUint16(grant, destination.PortFrom)
	return binary.BigEndian.AppendUint16(grant, destination.PortTo)
}

// appendSelector encodes kind(1) followed by:
//   - any: nothing;
//   - prefix: family(1) address(4|16) bits(1), masked and unmapped;
//   - range: family(1) start(4|16) end(4|16), unmapped, start <= end;
//   - capability: length(2) UTF-8 name.
func appendSelector(encoded []byte, selector Selector) ([]byte, error) {
	encoded = append(encoded, byte(selector.Kind))
	switch selector.Kind {
	case KindAny:
		return encoded, nil
	case KindPrefix:
		if !selector.Prefix.IsValid() {
			return nil, ErrInvalidRule
		}
		address := selector.Prefix.Addr().Unmap()
		bits := selector.Prefix.Bits()
		if bits < 0 || bits > address.BitLen() {
			return nil, ErrInvalidRule
		}
		prefix := netip.PrefixFrom(address, bits).Masked()
		encoded = appendAddress(encoded, prefix.Addr())
		return append(encoded, byte(bits)), nil //nolint:gosec // G115: 0–128, checked above
	case KindRange:
		start, end := selector.RangeStart.Unmap(), selector.RangeEnd.Unmap()
		if !start.IsValid() || !end.IsValid() || start.Is4() != end.Is4() || end.Less(start) {
			return nil, ErrInvalidRule
		}
		encoded = appendAddress(encoded, start)
		return append(encoded, addressBytes(end)...), nil
	case KindCapability:
		if selector.Capability == "" || len(selector.Capability) > MaximumCapabilityLength {
			return nil, ErrInvalidRule
		}
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(selector.Capability))) //nolint:gosec // G115: bounded by MaximumCapabilityLength
		return append(encoded, selector.Capability...), nil
	default:
		return nil, ErrInvalidRule
	}
}

func appendAddress(encoded []byte, address netip.Addr) []byte {
	if address.Is4() {
		encoded = append(encoded, 4)
	} else {
		encoded = append(encoded, 6)
	}
	return append(encoded, addressBytes(address)...)
}

func addressBytes(address netip.Addr) []byte {
	if address.Is4() {
		bytes := address.As4()
		return bytes[:]
	}
	bytes := address.As16()
	return bytes[:]
}
