// Package routedigest computes the route digest v1 of the subnets a router
// forwards into (docs/protocol/route-digest-v1.md): one SHA-256 value that
// Core computes over the served routes it sends a router and the router
// computes over the routes it actually serves, so the two can be compared.
//
// The digest is semantic: it hashes the sorted, de-duplicated set of
// (Site, prefix, masquerade) entries. How Sites list their prefixes, or in
// which order, does not change it.
//
// The package is pure computation; it performs no I/O.
package routedigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"unicode/utf8"

	"meshtransit.net/shared/policydigest"
)

// Version is the digest version this package computes.
const Version = 1

const (
	// MaximumEntries bounds the served prefixes of one router (mtcp-v1 §14).
	MaximumEntries = 4096
	// MaximumSiteRefLength bounds one Site reference (mtcp-v1 §7.6).
	MaximumSiteRefLength = 64

	domainSeparator = "meshtransit route digest v1\x00"
)

var (
	// ErrInvalidEntry reports an entry the digest cannot represent.
	ErrInvalidEntry = errors.New("routedigest: invalid entry")
	// ErrTooLarge reports more than MaximumEntries distinct entries.
	ErrTooLarge = errors.New("routedigest: too many entries")
)

// Digest has the same text form as a policy digest ("sha256:" and hex).
type Digest = policydigest.Digest

// Entry is one served prefix of one Site.
type Entry struct {
	SiteRef    string
	Prefix     netip.Prefix
	Masquerade bool
}

// Compute returns the digest of entries and how many distinct entries it
// covers.
func Compute(entries []Entry) (Digest, int, error) {
	// A valid map never holds more served prefixes (mtcp-v1 §14).
	if len(entries) > MaximumEntries {
		return Digest{}, 0, ErrTooLarge
	}
	encoded := make([][]byte, 0, len(entries))
	masquerade := make(map[routeKey]bool, len(entries))
	for _, entry := range entries {
		value, err := encode(entry)
		if err != nil {
			return Digest{}, 0, err
		}
		key := routeKey{siteRef: entry.SiteRef, prefix: entry.Prefix}
		if previous, seen := masquerade[key]; seen && previous != entry.Masquerade {
			return Digest{}, 0, ErrInvalidEntry
		}
		masquerade[key] = entry.Masquerade
		encoded = append(encoded, value)
	}
	slices.SortFunc(encoded, bytes.Compare)
	encoded = slices.CompactFunc(encoded, bytes.Equal)
	hash := sha256.New()
	hash.Write([]byte(domainSeparator))
	hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(encoded))))
	for _, value := range encoded {
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value)))) //nolint:gosec // G115: bounded by encode
		hash.Write(value)
	}
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return digest, len(encoded), nil
}

type routeKey struct {
	siteRef string
	prefix  netip.Prefix
}

// encode writes u16(len(site_ref)) || site_ref || family || address ||
// u8(bits) || u8(masquerade).
func encode(entry Entry) ([]byte, error) {
	prefix := entry.Prefix
	if len(entry.SiteRef) == 0 || len(entry.SiteRef) > MaximumSiteRefLength || !utf8.ValidString(entry.SiteRef) ||
		!prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Bits() == 0 {
		return nil, ErrInvalidEntry
	}
	value := binary.BigEndian.AppendUint16(nil, uint16(len(entry.SiteRef))) //nolint:gosec // G115: at most MaximumSiteRefLength
	value = append(value, entry.SiteRef...)
	if prefix.Addr().Is4() {
		value = append(value, 4)
	} else {
		value = append(value, 6)
	}
	value = append(value, prefix.Addr().AsSlice()...)
	value = append(value, uint8(prefix.Bits())) //nolint:gosec // G115: at most 128
	if entry.Masquerade {
		return append(value, 1), nil
	}
	return append(value, 0), nil
}
