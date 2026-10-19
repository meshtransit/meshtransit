// Package netadmin defines the narrow privileged boundary between meshd and meshnetd.
package netadmin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/routesettings"
)

const (
	protocolVersion = 5
	// maxMessageBytes fits a large routed route set (about 6,000 IPv4 or
	// 2,700 IPv6 prefixes) in one SEQPACKET message on Linux defaults; a
	// larger request is refused before it is sent.
	maxMessageBytes   = 128 << 10
	operationOpenTUN  = "open_tun"
	operationSetTUN   = "set_tun_routes"
	operationOpenDNS  = "open_dns"
	operationSetDNS   = "set_dns"
	operationResetDNS = "reset_dns"
	// operationSetRouted replaces the subnet routes of the data interface
	// (mtcp-v1 §7.6); the helper installs only those its local settings
	// admit.
	operationSetRouted = "set_routed_routes"
	maxTUNAddresses    = 8
	maxTUNRoutes       = 512
	maxAllowedPools    = 16
	maxDNSDomains      = 256
	maxDNSDomainBytes  = 16 << 10
	interfaceNameSize  = 16
)

var (
	// ErrProtocol indicates a malformed or unexpected helper response.
	ErrProtocol = errors.New("netadmin: protocol error")
	// ErrRemote indicates that meshnetd rejected a valid request.
	ErrRemote = errors.New("netadmin: helper rejected request")
	// ErrUnsupported indicates that privileged TUN setup is unavailable.
	ErrUnsupported = errors.New("netadmin: unsupported platform")
	// ErrTUNConfig indicates that requested addresses or routes are not safe host prefixes.
	ErrTUNConfig = errors.New("netadmin: invalid tun configuration")
)

// TUNConfig contains only bounded host prefixes derived from a validated map.
// Callers retain ownership of the input slices.
type TUNConfig struct {
	Addresses []netip.Prefix
	Routes    []netip.Prefix
}

// TUN is an owned TUN descriptor returned by meshnetd.
type TUN struct {
	File *os.File
	// Device is a TUN opened in this process, used on Windows, where the
	// service owns the Wintun adapter; File is nil then.
	Device    tun.Device
	Name      string
	MTU       int
	Addresses []netip.Prefix
	Routes    []netip.Prefix
}

// DNSEndpoint identifies the dedicated systemd-resolved link and the local
// unprivileged resolver endpoint opened for meshd by meshnetd.
type DNSEndpoint struct {
	InterfaceName string
	Resolver      netip.AddrPort
}

// DNSLink owns the non-persistent TUN descriptor backing one DNS endpoint.
// Closing File removes the dedicated link and its per-link resolved state.
type DNSLink struct {
	File     *os.File
	Endpoint DNSEndpoint
}

// DNSConfig is the complete, bounded per-link systemd-resolved transaction.
// Domain names are canonical lowercase names without trailing dots. A route
// domain of "." represents the DNS root.
type DNSConfig struct {
	Endpoint      DNSEndpoint
	SearchDomains []string
	RouteDomains  []string
	DefaultRoute  bool
}

type request struct {
	Version         int      `json:"version"`
	Operation       string   `json:"operation"`
	Addresses       []string `json:"addresses"`
	Routes          []string `json:"routes"`
	InterfaceName   string   `json:"interface_name,omitempty"`
	Resolver        string   `json:"resolver,omitempty"`
	SearchDomains   []string `json:"search_domains"`
	RouteDomains    []string `json:"route_domains"`
	DNSDefaultRoute bool     `json:"dns_default_route,omitempty"`
}

type response struct {
	Version       int      `json:"version"`
	OK            bool     `json:"ok"`
	Code          string   `json:"code,omitempty"`
	Message       string   `json:"message,omitempty"`
	InterfaceName string   `json:"interface_name,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	Addresses     []string `json:"addresses"`
	Routes        []string `json:"routes"`
	Resolver      string   `json:"resolver,omitempty"`
	// Refused lists up to 64 routed routes the helper did not install, and
	// RefusedTotal counts them all.
	Refused      []routeRefusal `json:"refused,omitempty"`
	RefusedTotal int            `json:"refused_total,omitempty"`
}

// RoutedResult is what the helper did with requested subnet routes: those
// installed and those its local settings refused.
type RoutedResult struct {
	Installed []netip.Prefix
	// Refused lists up to 64 refused routes; RefusedTotal counts them all.
	Refused      []routesettings.Refusal
	RefusedTotal int
}

// maximumReportedRefusals bounds the refusals one response lists; the
// response counts them all, and stays within maxMessageBytes.
const maximumReportedRefusals = 64

// routeRefusal is one routed route the helper refused, with a stable reason
// code (routesettings).
type routeRefusal struct {
	Prefix string `json:"prefix"`
	Reason string `json:"reason"`
}

func decodeMessage(payload []byte, target any) error {
	if len(payload) == 0 || len(payload) > maxMessageBytes {
		return fmt.Errorf("%w: message size is outside the allowed range", ErrProtocol)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decoding message: %w", ErrProtocol, err)
	}
	var extra struct{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: message must contain one json value", ErrProtocol)
	}

	return nil
}

type validatedRequest struct {
	operation string
	tun       TUNConfig
	dns       DNSConfig
	routed    []netip.Prefix
}

func validateRequest(value request) (validatedRequest, error) {
	if value.Version != protocolVersion {
		return validatedRequest{}, fmt.Errorf("%w: unsupported protocol version", ErrProtocol)
	}

	switch value.Operation {
	case operationOpenTUN, operationSetTUN:
		if value.Addresses == nil || value.Routes == nil || hasDNSRequestFields(value) {
			return validatedRequest{}, fmt.Errorf("%w: tun fields are invalid", ErrProtocol)
		}
		config, err := parseTUNConfig(value.Addresses, value.Routes)
		if err != nil {
			return validatedRequest{}, err
		}
		if !slices.Equal(value.Addresses, prefixStrings(config.Addresses)) ||
			!slices.Equal(value.Routes, prefixStrings(config.Routes)) {
			return validatedRequest{}, fmt.Errorf("%w: prefixes must be sorted and canonical", ErrTUNConfig)
		}

		return validatedRequest{operation: value.Operation, tun: config}, nil
	case operationSetRouted:
		if value.Addresses != nil || value.Routes == nil || len(value.Routes) > routesettings.MaximumRoutes ||
			hasDNSRequestFields(value) {
			return validatedRequest{}, fmt.Errorf("%w: routed route fields are invalid", ErrProtocol)
		}
		routed, err := parseRoutedRoutes(value.Routes)
		if err != nil {
			return validatedRequest{}, err
		}
		return validatedRequest{operation: value.Operation, routed: routed}, nil
	case operationOpenDNS, operationResetDNS:
		if value.Addresses != nil || value.Routes != nil || hasDNSConfigFields(value) {
			return validatedRequest{}, fmt.Errorf("%w: dns lifecycle fields are invalid", ErrProtocol)
		}

		return validatedRequest{operation: value.Operation}, nil
	case operationSetDNS:
		if value.Addresses != nil || value.Routes != nil ||
			value.SearchDomains == nil || value.RouteDomains == nil {
			return validatedRequest{}, fmt.Errorf("%w: dns configuration fields are invalid", ErrProtocol)
		}
		endpoint, err := parseDNSEndpoint(value.InterfaceName, value.Resolver)
		if err != nil {
			return validatedRequest{}, err
		}
		config := DNSConfig{
			Endpoint:      endpoint,
			SearchDomains: append([]string(nil), value.SearchDomains...),
			RouteDomains:  append([]string(nil), value.RouteDomains...),
			DefaultRoute:  value.DNSDefaultRoute,
		}
		if err := validateDNSConfig(config); err != nil {
			return validatedRequest{}, err
		}

		return validatedRequest{operation: value.Operation, dns: config}, nil
	default:
		return validatedRequest{}, fmt.Errorf("%w: unsupported operation", ErrProtocol)
	}
}

func validateResponse(value response, operation string) error {
	if value.Version != protocolVersion {
		return fmt.Errorf("%w: unsupported protocol version", ErrProtocol)
	}
	if value.OK {
		if value.Code != "" || value.Message != "" ||
			(operation != operationSetRouted && (value.Refused != nil || value.RefusedTotal != 0)) {
			return fmt.Errorf("%w: malformed success response", ErrProtocol)
		}
		switch operation {
		case operationOpenTUN:
			if value.InterfaceName == "" || value.MTU == 0 || value.Addresses == nil ||
				value.Routes == nil || value.Resolver != "" {
				return fmt.Errorf("%w: malformed open tun response", ErrProtocol)
			}
		case operationSetTUN:
			if value.InterfaceName != "" || value.Resolver != "" || value.MTU != 0 ||
				value.Addresses != nil || value.Routes != nil {
				return fmt.Errorf("%w: malformed set tun response", ErrProtocol)
			}
		case operationOpenDNS:
			if value.InterfaceName == "" || value.Resolver == "" || value.MTU != 0 ||
				value.Addresses != nil || value.Routes != nil {
				return fmt.Errorf("%w: malformed open dns response", ErrProtocol)
			}
		case operationSetDNS, operationResetDNS:
			if value.InterfaceName != "" || value.Resolver != "" || value.MTU != 0 ||
				value.Addresses != nil || value.Routes != nil || value.Refused != nil {
				return fmt.Errorf("%w: malformed dns response", ErrProtocol)
			}
		case operationSetRouted:
			if value.InterfaceName != "" || value.Resolver != "" || value.MTU != 0 ||
				value.Addresses != nil || value.Routes == nil || len(value.Refused) > maximumReportedRefusals ||
				value.RefusedTotal < len(value.Refused) || value.RefusedTotal > routesettings.MaximumRoutes {
				return fmt.Errorf("%w: malformed routed route response", ErrProtocol)
			}
		default:
			return fmt.Errorf("%w: unknown response operation", ErrProtocol)
		}

		return nil
	}
	if value.Code == "" || value.Message == "" || value.InterfaceName != "" || value.MTU != 0 ||
		len(value.Addresses) != 0 || len(value.Routes) != 0 || value.Resolver != "" || len(value.Refused) != 0 ||
		value.RefusedTotal != 0 {
		return fmt.Errorf("%w: malformed error response", ErrProtocol)
	}

	return nil
}

func hasDNSRequestFields(value request) bool {
	return hasDNSConfigFields(value) || value.SearchDomains != nil || value.RouteDomains != nil
}

func hasDNSConfigFields(value request) bool {
	return value.InterfaceName != "" || value.Resolver != "" || value.DNSDefaultRoute
}

func parseDNSEndpoint(interfaceName, resolver string) (DNSEndpoint, error) {
	if !validInterfaceName(interfaceName) {
		return DNSEndpoint{}, fmt.Errorf("%w: dns interface name is invalid", ErrProtocol)
	}
	address, err := netip.ParseAddrPort(resolver)
	if err != nil || address.String() != resolver || address.Addr().Is4In6() ||
		!address.Addr().IsGlobalUnicast() || address.Addr().IsLinkLocalUnicast() ||
		address.Port() < 1024 {
		return DNSEndpoint{}, fmt.Errorf("%w: dns resolver endpoint is invalid", ErrProtocol)
	}

	return DNSEndpoint{InterfaceName: interfaceName, Resolver: address}, nil
}

func validateDNSConfig(config DNSConfig) error {
	endpoint, err := parseDNSEndpoint(config.Endpoint.InterfaceName, config.Endpoint.Resolver.String())
	if err != nil || endpoint != config.Endpoint {
		return fmt.Errorf("%w: dns endpoint is invalid", ErrProtocol)
	}
	if len(config.SearchDomains)+len(config.RouteDomains) == 0 ||
		len(config.SearchDomains)+len(config.RouteDomains) > maxDNSDomains {
		return fmt.Errorf("%w: dns domain count is outside the allowed range", ErrProtocol)
	}
	seen := make(map[string]struct{}, len(config.SearchDomains)+len(config.RouteDomains))
	totalBytes := 0
	for _, domain := range config.SearchDomains {
		if !validDNSDomain(domain, false) {
			return fmt.Errorf("%w: dns search domain is invalid", ErrProtocol)
		}
		if _, exists := seen[domain]; exists {
			return fmt.Errorf("%w: dns domain is duplicated", ErrProtocol)
		}
		seen[domain] = struct{}{}
		totalBytes += len(domain)
	}
	for _, domain := range config.RouteDomains {
		if !validDNSDomain(domain, true) {
			return fmt.Errorf("%w: dns route domain is invalid", ErrProtocol)
		}
		if _, exists := seen[domain]; exists {
			return fmt.Errorf("%w: dns domain is duplicated", ErrProtocol)
		}
		seen[domain] = struct{}{}
		totalBytes += len(domain)
	}
	if totalBytes > maxDNSDomainBytes {
		return fmt.Errorf("%w: dns domain bytes exceed the allowed range", ErrProtocol)
	}
	hasRoot := slices.Contains(config.RouteDomains, ".")
	if config.DefaultRoute != hasRoot {
		return fmt.Errorf("%w: dns default route does not match root route", ErrProtocol)
	}

	return nil
}

func validDNSDomain(value string, allowRoot bool) bool {
	if value == "." {
		return allowRoot
	}
	if value == "" || len(value) > 253 || value != strings.ToLower(value) ||
		strings.HasSuffix(value, ".") {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}

	return true
}

// ValidInterfaceName reports whether name is one meshnetd can give a link:
// mesh* on Linux, or a kernel-named utunN on macOS.
func ValidInterfaceName(name string) bool { return validInterfaceName(name) }

// validInterfaceName accepts the names meshnetd gives its links (mesh*) and
// the names the macOS kernel gives tunnels (utun0 to utun9999).
func validInterfaceName(name string) bool {
	if len(name) > len("utun") && len(name) <= len("utun9999") && name[:4] == "utun" {
		for _, character := range name[4:] {
			if character < '0' || character > '9' {
				return false
			}
		}
		return true
	}
	if len(name) < len("mesh0") || len(name) >= interfaceNameSize || name[:4] != "mesh" {
		return false
	}
	for _, character := range name[4:] {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}

	return true
}

func parseTUNConfig(addressValues, routeValues []string) (TUNConfig, error) {
	addresses, err := parsePrefixStrings(addressValues)
	if err != nil {
		return TUNConfig{}, fmt.Errorf("%w: address is malformed", ErrTUNConfig)
	}
	routes, err := parsePrefixStrings(routeValues)
	if err != nil {
		return TUNConfig{}, fmt.Errorf("%w: route is malformed", ErrTUNConfig)
	}

	return normalizeTUNConfig(TUNConfig{Addresses: addresses, Routes: routes})
}

func parsePrefixStrings(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value {
			return nil, errors.New("prefix is not canonical")
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func normalizeTUNConfig(config TUNConfig) (TUNConfig, error) {
	addresses, err := normalizeHostPrefixes("address", config.Addresses, maxTUNAddresses)
	if err != nil {
		return TUNConfig{}, err
	}
	routes, err := normalizeRoutePrefixes(config.Routes, maxTUNRoutes)
	if err != nil {
		return TUNConfig{}, err
	}
	if len(routes) != 0 && len(addresses) == 0 {
		return TUNConfig{}, fmt.Errorf("%w: routes require an interface address", ErrTUNConfig)
	}
	for _, route := range routes {
		if slices.ContainsFunc(addresses, route.Overlaps) {
			return TUNConfig{}, fmt.Errorf("%w: route overlaps an interface address", ErrTUNConfig)
		}
	}

	return TUNConfig{Addresses: addresses, Routes: routes}, nil
}

// normalizeRoutePrefixes accepts canonical global unicast prefixes that do
// not overlap. meshd aggregates peer host routes exactly, so a route is one
// host or a block of hosts; the server then requires every route to lie
// wholly inside its allowlist, which is at most the safe overlay frame.
func normalizeRoutePrefixes(values []netip.Prefix, maximum int) ([]netip.Prefix, error) {
	if len(values) > maximum {
		return nil, fmt.Errorf("%w: too many routes", ErrTUNConfig)
	}
	prefixes := append([]netip.Prefix{}, values...)
	for index, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("%w: route must be a canonical global prefix", ErrTUNConfig)
		}
		address := prefix.Addr().Unmap()
		if prefix != prefix.Masked() || prefix.Addr() != address || prefix.Bits() == 0 ||
			!address.IsGlobalUnicast() || address.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("%w: route must be a canonical global prefix", ErrTUNConfig)
		}
		prefixes[index] = prefix
	}
	slices.SortFunc(prefixes, comparePrefixes)
	for index := 1; index < len(prefixes); index++ {
		if prefixes[index].Overlaps(prefixes[index-1]) {
			return nil, fmt.Errorf("%w: routes overlap", ErrTUNConfig)
		}
	}

	return prefixes, nil
}

func normalizeHostPrefixes(
	kind string,
	values []netip.Prefix,
	maximum int,
) ([]netip.Prefix, error) {
	if len(values) > maximum {
		return nil, fmt.Errorf("%w: too many %ss", ErrTUNConfig, kind)
	}
	prefixes := append([]netip.Prefix{}, values...)
	for index, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("%w: %s must be a canonical global host prefix", ErrTUNConfig, kind)
		}
		address := prefix.Addr().Unmap()
		if prefix != prefix.Masked() || prefix.Addr() != address ||
			prefix.Bits() != address.BitLen() || !address.IsGlobalUnicast() ||
			address.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("%w: %s must be a canonical global host prefix", ErrTUNConfig, kind)
		}
		prefixes[index] = netip.PrefixFrom(address, address.BitLen())
	}
	slices.SortFunc(prefixes, comparePrefixes)
	for index := 1; index < len(prefixes); index++ {
		if prefixes[index] == prefixes[index-1] {
			return nil, fmt.Errorf("%w: %s is duplicated", ErrTUNConfig, kind)
		}
	}

	return prefixes, nil
}

func comparePrefixes(left, right netip.Prefix) int {
	if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
		return comparison
	}

	return left.Bits() - right.Bits()
}

func prefixStrings(prefixes []netip.Prefix) []string {
	values := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		values[index] = prefix.String()
	}

	return values
}

// parseRoutedRoutes reads routed routes: canonical prefixes, sorted IPv4
// before IPv6 and by address and length, each listed once. Whether a route
// may be installed is the helper's local decision (routesettings.Admit).
func parseRoutedRoutes(values []string) ([]netip.Prefix, error) {
	routed := make([]netip.Prefix, 0, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || prefix != prefix.Masked() {
			return nil, fmt.Errorf("%w: routed route %q is not canonical", ErrTUNConfig, value)
		}
		if index > 0 && compareRoutedPrefixes(routed[index-1], prefix) >= 0 {
			return nil, fmt.Errorf("%w: routed routes must be sorted and unique", ErrTUNConfig)
		}
		routed = append(routed, prefix)
	}
	return routed, nil
}

func compareRoutedPrefixes(first, second netip.Prefix) int {
	if order := first.Addr().Compare(second.Addr()); order != 0 {
		return order
	}
	return first.Bits() - second.Bits()
}
