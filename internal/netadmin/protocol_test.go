package netadmin

import (
	"errors"
	"net/netip"
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
	if err := validateResponse(valid); err != nil {
		t.Fatalf("validateResponse() error = %v", err)
	}
	valid.Code = "unexpected"
	if err := validateResponse(valid); !errors.Is(err, ErrProtocol) {
		t.Fatalf("validateResponse() error = %v, want ErrProtocol", err)
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
