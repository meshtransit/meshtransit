package httpapi

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const (
	maximumForwardedForBytes   = 1024
	maximumForwardedForEntries = 16
)

var errInvalidClientIP = errors.New("invalid client IP")

type clientIPResolver struct {
	trustedProxyPrefixes []netip.Prefix
}

func newClientIPResolver(prefixes []netip.Prefix) (clientIPResolver, error) {
	trusted := make([]netip.Prefix, len(prefixes))
	for index, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return clientIPResolver{}, errInvalidClientIP
		}
		trusted[index] = prefix
	}
	return clientIPResolver{trustedProxyPrefixes: trusted}, nil
}

func (resolver clientIPResolver) Resolve(request *http.Request) (netip.Addr, error) {
	if request == nil {
		return netip.Addr{}, errInvalidClientIP
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errInvalidClientIP
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errInvalidClientIP
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
		return netip.Addr{}, errInvalidClientIP
	}
	parts := strings.Split(joined, ",")
	if len(parts) == 0 || len(parts) > maximumForwardedForEntries {
		return netip.Addr{}, errInvalidClientIP
	}
	forwarded := make([]netip.Addr, len(parts))
	for index, part := range parts {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(part))
		if parseErr != nil {
			return netip.Addr{}, errInvalidClientIP
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

func (resolver clientIPResolver) trusted(address netip.Addr) bool {
	for _, prefix := range resolver.trustedProxyPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
