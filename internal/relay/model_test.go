package relay

import (
	"crypto/ecdh"
	"net/netip"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	config := testConfig()
	validated, err := Validate(config)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	config.Regions[1] = Region{ID: 99}
	config.Peers[0].HomeRegion = 99
	if validated.Regions[1].ID != 1 || validated.Peers[0].HomeRegion != 1 {
		t.Fatal("Validate() retained caller-owned configuration")
	}
}

func TestValidateRejectsInvalidAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "zero private key",
			mutate: func(config *Config) {
				config.PrivateKey = Key{}
			},
		},
		{
			name: "mismatched public key",
			mutate: func(config *Config) {
				config.PublicKey[0] ^= 0xff
			},
		},
		{
			name: "missing home region",
			mutate: func(config *Config) {
				config.HomeRegion = 2
			},
		},
		{
			name: "duplicate peer",
			mutate: func(config *Config) {
				config.Peers = append(config.Peers, config.Peers[0])
			},
		},
		{
			name: "unknown peer region",
			mutate: func(config *Config) {
				config.Peers[0].HomeRegion = 2
			},
		},
		{
			name: "invalid peer address",
			mutate: func(config *Config) {
				config.Peers[0].Address = netip.MustParseAddr("127.0.0.1")
			},
		},
		{
			name: "empty node hostname",
			mutate: func(config *Config) {
				region := config.Regions[1]
				region.Nodes[0].HostName = ""
				config.Regions[1] = region
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig()
			test.mutate(&config)
			if _, err := Validate(config); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestFingerprintIsDeterministicAndExcludesPrivateKey(t *testing.T) {
	t.Parallel()

	first := testConfig()
	second := testConfig()
	second.PrivateKey[0] = 9
	if Fingerprint(first) != Fingerprint(second) {
		t.Fatal("Fingerprint() changed with private key")
	}
	region := second.Regions[1]
	region.Nodes[0].HostName = "relay-2.example.com"
	second.Regions[1] = region
	if Fingerprint(first) == Fingerprint(second) {
		t.Fatal("Fingerprint() ignored public relay authority change")
	}
}

func testConfig() Config {
	privateKey := Key{1}
	curvePrivate, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil {
		panic(err)
	}
	publicKey := Key(curvePrivate.PublicKey().Bytes())
	peerKey := Key{2}

	return Config{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		HomeRegion: 1,
		Regions: map[int]Region{
			1: {
				ID: 1,
				Nodes: []Node{{
					Name:     "relay-1",
					HostName: "relay.example.com",
					Port:     443,
				}},
			},
		},
		Peers: []Peer{{
			Key:        peerKey,
			HomeRegion: 1,
			Address:    netip.MustParseAddr("100.64.0.2"),
		}},
	}
}
