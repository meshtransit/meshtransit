// Package dnsdigest computes the DNS digest v1 of the DNS routes and search
// domains of a node (docs/protocol/dns-digest-v1.md): one SHA-256 value that
// Core computes over the DNS configuration it sends a node and the node
// computes over the configuration it applied to its host, so the two can be
// compared.
//
// The digest covers each route's suffix, resolvers in order, and failure
// mode, the routes in suffix order, and the search domains in order. Records
// are not covered.
//
// The package is pure computation; it performs no I/O.
package dnsdigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/shared/policydigest"
)

// Version is the digest version this package computes.
const Version = 1

const (
	// MaximumRoutes bounds the routes of one configuration: the zones of a
	// map (256), the mesh suffix and room to spare.
	MaximumRoutes = 1024
	// MaximumResolvers bounds the resolvers of one route (mtcp-v1 §7.3).
	MaximumResolvers = 4
	// MaximumSearchDomains bounds the search domains (mtcp-v1 §7.3).
	MaximumSearchDomains = 16
	// maximumNameLength bounds a domain (RFC 1035).
	maximumNameLength = 253

	domainSeparator = "meshtransit dns digest v1\x00"
	defaultPort     = 53
	flagUnavailable = 1 << 0
	flagFailOpen    = 1 << 1
)

var (
	// ErrInvalidRoute reports a route or search domain the digest cannot
	// represent.
	ErrInvalidRoute = errors.New("dnsdigest: invalid route")
	// ErrTooLarge reports more routes, resolvers or search domains than the
	// bounds.
	ErrTooLarge = errors.New("dnsdigest: too many routes")
)

// Digest has the same text form as a policy digest ("sha256:" and hex).
type Digest = policydigest.Digest

// Resolver is one resolver of a route: an address and a port, 0 being 53.
type Resolver struct {
	Address netip.Addr
	Port    uint16
}

// Route is one DNS route: a suffix ("." for every name), its resolvers in
// the order asked, and its failure mode.
type Route struct {
	Suffix      string
	Resolvers   []Resolver
	Unavailable bool
	FailOpen    bool
}

// Compute returns the digest of routes and search domains and how many
// routes it covers.
func Compute(routes []Route, searchDomains []string) (Digest, int, error) {
	if len(routes) > MaximumRoutes || len(searchDomains) > MaximumSearchDomains {
		return Digest{}, 0, ErrTooLarge
	}
	encoded := make([][]byte, 0, len(routes))
	for _, route := range routes {
		value, err := encodeRoute(route)
		if err != nil {
			return Digest{}, 0, err
		}
		encoded = append(encoded, value)
	}
	// Each route starts with its suffix, so two routes of one suffix are
	// adjacent in byte order.
	slices.SortFunc(encoded, bytes.Compare)
	for index := 1; index < len(encoded); index++ {
		if routeSuffix(encoded[index-1]) == routeSuffix(encoded[index]) {
			return Digest{}, 0, ErrInvalidRoute
		}
	}
	hash := sha256.New()
	hash.Write([]byte(domainSeparator))
	hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(encoded))))
	for _, value := range encoded {
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value)))) //nolint:gosec // G115: bounded by encodeRoute
		hash.Write(value)
	}
	hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(searchDomains))))
	for _, domain := range searchDomains {
		if domain == "." || !validName(domain) {
			return Digest{}, 0, ErrInvalidRoute
		}
		hash.Write(binary.BigEndian.AppendUint16(nil, uint16(len(domain)))) //nolint:gosec // G115: at most 253
		hash.Write([]byte(domain))
	}
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return digest, len(encoded), nil
}

// encodeRoute writes u16(len(suffix)) || suffix || u8(flags) ||
// u8(count(resolvers)) || for each resolver: family || address || u16(port).
func encodeRoute(route Route) ([]byte, error) {
	if !validName(route.Suffix) || len(route.Resolvers) > MaximumResolvers ||
		(route.Unavailable && len(route.Resolvers) != 0) {
		return nil, ErrInvalidRoute
	}
	value := binary.BigEndian.AppendUint16(nil, uint16(len(route.Suffix))) //nolint:gosec // G115: at most 253
	value = append(value, route.Suffix...)
	var flags uint8
	if route.Unavailable {
		flags |= flagUnavailable
	}
	if route.FailOpen {
		flags |= flagFailOpen
	}
	value = append(value, flags, uint8(len(route.Resolvers))) //nolint:gosec // G115: at most MaximumResolvers
	for _, resolver := range route.Resolvers {
		address := resolver.Address
		if !address.IsValid() || address.Zone() != "" {
			return nil, ErrInvalidRoute
		}
		address = address.Unmap()
		if address.Is4() {
			value = append(value, 4)
		} else {
			value = append(value, 6)
		}
		value = append(value, address.AsSlice()...)
		port := resolver.Port
		if port == 0 {
			port = defaultPort
		}
		value = binary.BigEndian.AppendUint16(value, port)
	}
	return value, nil
}

// routeSuffix reads the suffix an encoded route starts with.
func routeSuffix(value []byte) string {
	length := int(binary.BigEndian.Uint16(value))
	return string(value[2 : 2+length])
}

// validName accepts "." and lower-case names of letters, digits, hyphens and
// underscores, without a trailing dot or empty labels.
func validName(name string) bool {
	if name == "." {
		return true
	}
	if name == "" || len(name) > maximumNameLength {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
				return false
			}
		}
	}
	return true
}
