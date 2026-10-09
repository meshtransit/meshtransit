// Package clientip resolves the client address of an HTTP request behind
// trusted reverse proxies: the rightmost X-Forwarded-For hop that is not a
// trusted proxy, or the peer itself when the peer is untrusted.
package clientip

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

const (
	maximumForwardedForBytes   = 1024
	maximumForwardedForEntries = 16
)

// ErrInvalid reports an unusable peer address or forwarding header.
var ErrInvalid = errors.New("invalid client IP")

// Resolver selects the client address using a fixed trusted-proxy set.
type Resolver struct {
	trustedProxyPrefixes []netip.Prefix
}

// NewResolver validates the trusted proxy prefixes (each must be masked).
func NewResolver(prefixes []netip.Prefix) (Resolver, error) {
	trusted := make([]netip.Prefix, len(prefixes))
	for index, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return Resolver{}, ErrInvalid
		}
		trusted[index] = prefix
	}
	return Resolver{trustedProxyPrefixes: trusted}, nil
}

// Resolve returns the request's client address.
func (resolver Resolver) Resolve(request *http.Request) (netip.Addr, error) {
	if request == nil {
		return netip.Addr{}, ErrInvalid
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, ErrInvalid
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, ErrInvalid
	}
	peer = peer.Unmap()
	if !resolver.trusted(peer) {
		return peer, nil
	}

	values := request.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer, nil
	}
	joined := strings.Join(values, ",")
	if len(joined) == 0 || len(joined) > maximumForwardedForBytes {
		return netip.Addr{}, ErrInvalid
	}
	parts := strings.Split(joined, ",")
	if len(parts) == 0 || len(parts) > maximumForwardedForEntries {
		return netip.Addr{}, ErrInvalid
	}
	forwarded := make([]netip.Addr, len(parts))
	for index, part := range parts {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(part))
		if parseErr != nil {
			return netip.Addr{}, ErrInvalid
		}
		forwarded[index] = address.Unmap()
	}
	for index := len(forwarded) - 1; index >= 0; index-- {
		if !resolver.trusted(forwarded[index]) {
			return forwarded[index], nil
		}
	}
	return forwarded[0], nil
}

func (resolver Resolver) trusted(address netip.Addr) bool {
	for _, prefix := range resolver.trustedProxyPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// TrustedProxies returns a copy of the trusted proxy prefixes.
func (resolver Resolver) TrustedProxies() []netip.Prefix {
	return slices.Clone(resolver.trustedProxyPrefixes)
}
