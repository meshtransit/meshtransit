package netadmin

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestDecodeMessageRejectsUnknownAndTrailingValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
	}{
		{name: "unknown field", payload: `{"version":3,"operation":"open_tun","addresses":[],"routes":[],"extra":true}`},
		{name: "trailing value", payload: `{"version":3,"operation":"open_tun","addresses":[],"routes":[]}{}`},
		{name: "empty message", payload: ``},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var decoded request
			if err := decodeMessage([]byte(test.payload), &decoded); !errors.Is(err, ErrProtocol) {
				t.Fatalf("decodeMessage() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	valid := request{
		Version:   protocolVersion,
		Operation: operationOpenTUN,
		Addresses: []string{},
		Routes:    []string{},
	}
	if _, err := validateRequest(valid); err != nil {
		t.Fatalf("validateRequest() error = %v", err)
	}
	invalidVersion := valid
	invalidVersion.Version++
	if _, err := validateRequest(invalidVersion); !errors.Is(err, ErrProtocol) {
		t.Fatalf("version error = %v, want ErrProtocol", err)
	}
	invalidOperation := valid
	invalidOperation.Operation = "delete_host"
	if _, err := validateRequest(invalidOperation); !errors.Is(err, ErrProtocol) {
		t.Fatalf("operation error = %v, want ErrProtocol", err)
	}
	missingPrefixes := valid
	missingPrefixes.Addresses = nil
	if _, err := validateRequest(missingPrefixes); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing prefixes error = %v, want ErrProtocol", err)
	}
}

func TestValidateResponse(t *testing.T) {
	t.Parallel()

	valid := response{
		Version:       protocolVersion,
		OK:            true,
		InterfaceName: "mesh0",
		MTU:           1280,
		Addresses:     []string{},
		Routes:        []string{},
	}
	if err := validateResponse(valid, operationOpenTUN); err != nil {
		t.Fatalf("validateResponse() error = %v", err)
	}
	valid.Code = "unexpected"
	if err := validateResponse(valid, operationOpenTUN); !errors.Is(err, ErrProtocol) {
		t.Fatalf("validateResponse() error = %v, want ErrProtocol", err)
	}
	if err := validateResponse(response{Version: protocolVersion, OK: true}, operationSetTUN); err != nil {
		t.Fatalf("validateResponse(set tun) error = %v", err)
	}
}

func TestValidateDNSConfig(t *testing.T) {
	t.Parallel()

	valid := validDNSConfigForTest()
	if err := validateDNSConfig(valid); err != nil {
		t.Fatalf("validateDNSConfig() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*DNSConfig)
	}{
		{
			name: "privileged resolver port",
			mutate: func(config *DNSConfig) {
				config.Endpoint.Resolver = netip.MustParseAddrPort("192.0.2.53:53")
			},
		},
		{
			name: "uppercase domain",
			mutate: func(config *DNSConfig) {
				config.SearchDomains[0] = "Mesh.Example"
			},
		},
		{
			name: "duplicate domain",
			mutate: func(config *DNSConfig) {
				config.RouteDomains[1] = "mesh.example"
			},
		},
		{
			name: "default route mismatch",
			mutate: func(config *DNSConfig) {
				config.DefaultRoute = false
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			config := validDNSConfigForTest()
			test.mutate(&config)
			if err := validateDNSConfig(config); !errors.Is(err, ErrProtocol) {
				t.Fatalf("validateDNSConfig() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func validDNSConfigForTest() DNSConfig {
	return DNSConfig{
		Endpoint: DNSEndpoint{
			InterfaceName: "meshdns0",
			Resolver:      netip.MustParseAddrPort("192.0.2.53:1053"),
		},
		SearchDomains: []string{"mesh.example"},
		RouteDomains:  []string{".", "64.100.in-addr.arpa"},
		DefaultRoute:  true,
	}
}

func TestNormalizeTUNConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config TUNConfig
	}{
		{
			name: "subnet address",
			config: TUNConfig{
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")},
			},
		},
		{
			name: "duplicate route",
			config: TUNConfig{
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				Routes: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.2/32"),
					netip.MustParsePrefix("100.64.0.2/32"),
				},
			},
		},
		{
			name: "route overlaps address",
			config: TUNConfig{
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				Routes:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
			},
		},
		{
			name: "overlapping routes",
			config: TUNConfig{
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32")},
				Routes: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.0/30"),
					netip.MustParsePrefix("100.64.0.2/32"),
				},
			},
		},
		{
			name: "route covers address",
			config: TUNConfig{
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				Routes:    []netip.Prefix{netip.MustParsePrefix("100.64.0.0/30")},
			},
		},
		{
			name: "route not canonical",
			config: TUNConfig{
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32")},
				Routes:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/30")},
			},
		},
		{
			name: "default route",
			config: TUNConfig{
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32")},
				Routes:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		},
		{
			name: "route without address",
			config: TUNConfig{
				Routes: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := normalizeTUNConfig(test.config); !errors.Is(err, ErrTUNConfig) {
				t.Fatalf("normalizeTUNConfig() error = %v, want ErrTUNConfig", err)
			}
		})
	}
}

// TestNormalizeTUNConfigAcceptsAggregatedRoutes: meshd sends peer routes
// aggregated exactly (prefixset.Summarize); the helper takes canonical
// prefixes that cover no interface address and do not overlap.
func TestNormalizeTUNConfigAcceptsAggregatedRoutes(t *testing.T) {
	t.Parallel()
	config, err := normalizeTUNConfig(TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		Routes: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.4/30"),
			netip.MustParsePrefix("100.64.0.0/31"),
			netip.MustParsePrefix("fd07::/124"),
		},
	})
	if err != nil {
		t.Fatalf("normalizeTUNConfig() error = %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/31"),
		netip.MustParsePrefix("100.64.0.4/30"),
		netip.MustParsePrefix("fd07::/124"),
	}
	if !slices.Equal(config.Routes, want) {
		t.Fatalf("routes = %v, want %v", config.Routes, want)
	}
}
