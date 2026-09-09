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
)

const (
	protocolVersion  = 3
	maxMessageBytes  = 32 << 10
	operationOpenTUN = "open_tun"
	maxTUNAddresses  = 8
	maxTUNRoutes     = 512
	maxAllowedPools  = 16
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
	File      *os.File
	Name      string
	MTU       int
	Addresses []netip.Prefix
	Routes    []netip.Prefix
}

type request struct {
	Version   int      `json:"version"`
	Operation string   `json:"operation"`
	Addresses []string `json:"addresses"`
	Routes    []string `json:"routes"`
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

func validateRequest(value request) (TUNConfig, error) {
	if value.Version != protocolVersion {
		return TUNConfig{}, fmt.Errorf("%w: unsupported protocol version", ErrProtocol)
	}
	if value.Operation != operationOpenTUN {
		return TUNConfig{}, fmt.Errorf("%w: unsupported operation", ErrProtocol)
	}
	if value.Addresses == nil || value.Routes == nil {
		return TUNConfig{}, fmt.Errorf("%w: prefix arrays are required", ErrProtocol)
	}

	config, err := parseTUNConfig(value.Addresses, value.Routes)
	if err != nil {
		return TUNConfig{}, err
	}
	if !slices.Equal(value.Addresses, prefixStrings(config.Addresses)) ||
		!slices.Equal(value.Routes, prefixStrings(config.Routes)) {
		return TUNConfig{}, fmt.Errorf("%w: prefixes must be sorted and canonical", ErrTUNConfig)
	}

	return config, nil
}

func validateResponse(value response) error {
	if value.Version != protocolVersion {
		return fmt.Errorf("%w: unsupported protocol version", ErrProtocol)
	}
	if value.OK {
		if value.Code != "" || value.Message != "" || value.InterfaceName == "" || value.MTU == 0 ||
			value.Addresses == nil || value.Routes == nil {
			return fmt.Errorf("%w: malformed success response", ErrProtocol)
		}

		return nil
	}
	if value.Code == "" || value.Message == "" || value.InterfaceName != "" || value.MTU != 0 ||
		len(value.Addresses) != 0 || len(value.Routes) != 0 {
		return fmt.Errorf("%w: malformed error response", ErrProtocol)
	}

	return nil
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
	routes, err := normalizeHostPrefixes("route", config.Routes, maxTUNRoutes)
	if err != nil {
		return TUNConfig{}, err
	}
	if len(routes) != 0 && len(addresses) == 0 {
		return TUNConfig{}, fmt.Errorf("%w: routes require an interface address", ErrTUNConfig)
	}
	addressSet := make(map[netip.Prefix]struct{}, len(addresses))
	for _, address := range addresses {
		addressSet[address] = struct{}{}
	}
	for _, route := range routes {
		if _, exists := addressSet[route]; exists {
			return TUNConfig{}, fmt.Errorf("%w: route overlaps an interface address", ErrTUNConfig)
		}
	}

	return TUNConfig{Addresses: addresses, Routes: routes}, nil
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
