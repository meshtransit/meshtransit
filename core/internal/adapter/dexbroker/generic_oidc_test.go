//go:build dexbroker

package dexbroker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dexoidc "github.com/dexidp/dex/connector/oidc"
	"github.com/dexidp/dex/storage/memory"

	"meshtransit.net/core/internal/platform/config"
)

func genericTestEndpoints(issuer string) OIDCProviderEndpoints {
	return OIDCProviderEndpoints{
		DiscoveryURL:     discoveryURLOf(issuer),
		AuthorizationURL: strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/auth",
		TokenURL:         strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/token",
		JWKSURL:          strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/certs",
	}
}

func genericServiceTestOptions(t *testing.T) ServiceOptions {
	t.Helper()
	options := validServiceTestOptions(t)
	issuer := "https://sso.example.test:8443/realms/corp"
	options.OIDCConnectors[0].ID = "oidc-0123456789abcdef"
	options.OIDCConnectors[0].DisplayName = "Corp SSO"
	options.OIDCConnectors[0].Issuer = issuer
	options.OIDCConnectors[0].Endpoints = genericTestEndpoints(issuer)
	options.OIDCConnectors[0].ClientID = "meshtransit"
	return options
}

func fingerprintOf(t *testing.T, options ServiceOptions) string {
	t.Helper()
	value, err := CalculateConfigurationFingerprint(options)
	if err != nil {
		t.Fatalf("CalculateConfigurationFingerprint() error = %v", err)
	}
	return value
}

func testCAFile(t *testing.T, contents []byte) config.TrustFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	file, err := config.NewTrustFile(path)
	if err != nil {
		t.Fatalf("NewTrustFile() error = %v", err)
	}
	return file
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testLeafPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sso.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, DNSNames: []string{"sso.example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestGenericConnectorAcceptsPortAndTrailingSlashIssuer(t *testing.T) {
	options := genericServiceTestOptions(t)
	fingerprintOf(t, options)
	issuer := "https://tenant.example.test/"
	options.OIDCConnectors[0].Issuer = issuer
	options.OIDCConnectors[0].Endpoints = genericTestEndpoints(issuer)
	if options.OIDCConnectors[0].Endpoints.DiscoveryURL != "https://tenant.example.test/.well-known/openid-configuration" {
		t.Fatalf("discovery URL = %q", options.OIDCConnectors[0].Endpoints.DiscoveryURL)
	}
	fingerprintOf(t, options)
}

func TestGenericConnectorRejectsInvalidOptions(t *testing.T) {
	tests := map[string]func(*OIDCConnectorOptions){
		"issuer two slashes": func(c *OIDCConnectorOptions) { c.Issuer += "//" },
		"issuer port 443": func(c *OIDCConnectorOptions) {
			c.Issuer = "https://sso.example.test:443/realms/corp"
			c.Endpoints = genericTestEndpoints(c.Issuer)
		},
		"issuer port zero": func(c *OIDCConnectorOptions) {
			c.Issuer = "https://sso.example.test:0/realms/corp"
			c.Endpoints = genericTestEndpoints(c.Issuer)
		},
		"discovery elsewhere": func(c *OIDCConnectorOptions) {
			c.Endpoints.DiscoveryURL = "https://other.example.test/.well-known/openid-configuration"
		},
		"userinfo http":       func(c *OIDCConnectorOptions) { c.Endpoints.UserInfoURL = "http://sso.example.test/userinfo" },
		"userinfo query":      func(c *OIDCConnectorOptions) { c.Endpoints.UserInfoURL = "https://sso.example.test/userinfo?x=1" },
		"unknown prompt":      func(c *OIDCConnectorOptions) { c.Prompt = "consent" },
		"unknown email mode":  func(c *OIDCConnectorOptions) { c.EmailMode = "untrusted" },
		"unknown token auth":  func(c *OIDCConnectorOptions) { c.TokenAuth = "private_key_jwt" },
		"claim with space":    func(c *OIDCConnectorOptions) { c.NameClaim = "given name" },
		"claim leading digit": func(c *OIDCConnectorOptions) { c.NameClaim = "1name" },
		"claim too long":      func(c *OIDCConnectorOptions) { c.NameClaim = strings.Repeat("a", 65) },
		"public network": func(c *OIDCConnectorOptions) {
			c.PrivateNetworks = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}
		},
		"unmasked network": func(c *OIDCConnectorOptions) {
			c.PrivateNetworks = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/16")}
		},
		"all shared address space": func(c *OIDCConnectorOptions) {
			c.PrivateNetworks = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
		},
		"wider than private": func(c *OIDCConnectorOptions) {
			c.PrivateNetworks = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/7")}
		},
		"metadata host route": func(c *OIDCConnectorOptions) {
			c.PrivateNetworks = []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}
		},
		"too many networks": func(c *OIDCConnectorOptions) {
			for index := range maximumPrivateNetworks + 1 {
				c.PrivateNetworks = append(c.PrivateNetworks, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index), 0, 0}), 16))
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := genericServiceTestOptions(t)
			mutate(&options.OIDCConnectors[0])
			if _, err := CalculateConfigurationFingerprint(options); !errors.Is(err, errInvalidConfiguration) {
				t.Fatalf("CalculateConfigurationFingerprint() error = %v", err)
			}
		})
	}
}

func TestGenericConnectorOptionsBindFingerprint(t *testing.T) {
	base := fingerprintOf(t, genericServiceTestOptions(t))
	ca := testCAPEM(t)
	mutations := map[string]func(*OIDCConnectorOptions){
		"prompt login": func(c *OIDCConnectorOptions) { c.Prompt = PromptLogin },
		"prompt omit":  func(c *OIDCConnectorOptions) { c.Prompt = PromptOmit },
		"name claim":   func(c *OIDCConnectorOptions) { c.NameClaim = "preferred_username" },
		"email assume": func(c *OIDCConnectorOptions) { c.EmailMode = EmailAssume },
		"token basic":  func(c *OIDCConnectorOptions) { c.TokenAuth = TokenAuthBasic },
		"token post":   func(c *OIDCConnectorOptions) { c.TokenAuth = TokenAuthPost },
		"userinfo": func(c *OIDCConnectorOptions) {
			c.Endpoints.UserInfoURL = "https://sso.example.test:8443/realms/corp/protocol/openid-connect/userinfo"
		},
		"private network": func(c *OIDCConnectorOptions) {
			c.PrivateNetworks = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
		},
	}
	seen := map[string]string{base: "base"}
	for name, mutate := range mutations {
		options := genericServiceTestOptions(t)
		mutate(&options.OIDCConnectors[0])
		value := fingerprintOf(t, options)
		if other, exists := seen[value]; exists {
			t.Fatalf("%s fingerprint equals %s", name, other)
		}
		seen[value] = name
	}
	withCA := genericServiceTestOptions(t)
	withCA.OIDCConnectors[0].CAFile = testCAFile(t, ca)
	first := fingerprintOf(t, withCA)
	if _, exists := seen[first]; exists {
		t.Fatal("CA did not change the fingerprint")
	}
	withCA.OIDCConnectors[0].CAFile = testCAFile(t, testCAPEM(t))
	if fingerprintOf(t, withCA) == first {
		t.Fatal("another CA kept the fingerprint")
	}
}

func TestGenericConnectorRefusesBadCABundle(t *testing.T) {
	ca := testCAPEM(t)
	bundles := map[string][]byte{
		"empty":       {},
		"not pem":     []byte("hello\n"),
		"private key": append(append([]byte{}, ca...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})...),
		"trailing":    append(append([]byte{}, ca...), []byte("junk")...),
		"bad der":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
		"leading":     append([]byte("junk\n"), ca...),
		"between":     append(append(append([]byte{}, ca...), []byte("junk\n")...), ca...),
		"leaf":        testLeafPEM(t),
		"too big":     []byte(strings.Repeat(string(ca), maximumConnectorCABytes/len(ca)+1)),
	}
	for name, bundle := range bundles {
		t.Run(name, func(t *testing.T) {
			options := genericServiceTestOptions(t)
			options.OIDCConnectors[0].CAFile = testCAFile(t, bundle)
			if _, err := CalculateConfigurationFingerprint(options); !errors.Is(err, errInvalidConfiguration) {
				t.Fatalf("CalculateConfigurationFingerprint() error = %v", err)
			}
		})
	}
	options := genericServiceTestOptions(t)
	options.OIDCConnectors[0].CAFile = testCAFile(t, append(append([]byte{}, ca...), testCAPEM(t)...))
	fingerprintOf(t, options)
}

func TestGenericConnectorMapsOptionsIntoDex(t *testing.T) {
	issuer := "https://sso.example.test:8443/realms/corp"
	endpoints := genericTestEndpoints(issuer)
	endpoints.UserInfoURL = issuer + "/protocol/openid-connect/userinfo"
	cases := []struct {
		name      string
		connector componentOIDCConnector
		prompt    string
		check     func(dexoidc.Config) bool
	}{
		{
			name:      "defaults",
			connector: componentOIDCConnector{},
			prompt:    "prompt=select_account",
			check: func(c dexoidc.Config) bool {
				return c.UserNameKey == "" && !c.GetUserInfo && !c.InsecureSkipEmailVerified && c.BasicAuthUnsupported == nil
			},
		},
		{
			name: "all set",
			connector: componentOIDCConnector{
				prompt: PromptLogin, nameClaim: "preferred_username", emailMode: EmailAssume,
				tokenAuth: TokenAuthPost, endpoints: endpoints,
			},
			prompt: "prompt=login",
			check: func(c dexoidc.Config) bool {
				return c.UserNameKey == "preferred_username" && c.GetUserInfo && c.InsecureSkipEmailVerified &&
					c.BasicAuthUnsupported != nil && *c.BasicAuthUnsupported
			},
		},
		{
			name:      "omit and basic",
			connector: componentOIDCConnector{prompt: PromptOmit, tokenAuth: TokenAuthBasic},
			prompt:    "",
			check: func(c dexoidc.Config) bool {
				return c.BasicAuthUnsupported != nil && !*c.BasicAuthUnsupported
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			connector := test.connector
			connector.id, connector.displayName, connector.generation = "oidc-0123456789abcdef", "Corp SSO", 1
			connector.issuer, connector.clientID, connector.clientSecret = issuer, "meshtransit", strings.Repeat("c", 48)
			if connector.endpoints.DiscoveryURL == "" {
				connector.endpoints = genericTestEndpoints(issuer)
			}
			configured, err := withImmutableConfiguration(memory.New(componentTestLogger()), "https://id.example.test/oauth2",
				componentConfiguration{connectors: []componentOIDCConnector{connector}, clients: []componentClient{{
					id: "meshtransit-core", displayName: "MeshTransit Core", generation: 1,
					secret: strings.Repeat("b", 48), redirectURI: "https://app.example.test/auth/callback",
				}}})
			if err != nil {
				t.Fatalf("withImmutableConfiguration() error = %v", err)
			}
			connectors, err := configured.ListConnectors(t.Context())
			if err != nil || len(connectors) != 1 {
				t.Fatalf("ListConnectors() = %d, %v", len(connectors), err)
			}
			var decoded dexoidc.Config
			if err := json.Unmarshal(connectors[0].Config, &decoded); err != nil {
				t.Fatalf("decode: %v", err)
			}
			authURL := decoded.ProviderDiscoveryOverrides.AuthURL
			if test.prompt == "" && strings.Contains(authURL, "prompt=") ||
				test.prompt != "" && !strings.HasSuffix(authURL, "?"+test.prompt) {
				t.Fatalf("authorization URL = %q", authURL)
			}
			// The unsafe Dex options stay unset whatever the connector says.
			if decoded.UserIDKey != "" || decoded.InsecureEnableGroups || decoded.IssuerAlias != "" ||
				decoded.InsecureSkipVerify || decoded.OverrideClaimMapping || len(decoded.HostedDomains) != 0 ||
				decoded.ClaimMapping != (dexoidc.Config{}).ClaimMapping || !test.check(decoded) {
				t.Fatalf("Dex config = %+v", decoded)
			}
		})
	}
}

func TestValidOutboundIPHonoursPrivateNetworks(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd12:3456::/32")}
	tests := []struct {
		address string
		valid   bool
	}{
		{address: "10.20.1.5", valid: true},
		{address: "fd12:3456::1", valid: true},
		{address: "10.21.1.5"},
		{address: "192.168.1.1"},
		{address: "172.16.0.1"},
		{address: "100.64.0.1"},
		{address: "fd00:ec2::254"},
		{address: "100.100.100.200"},
		{address: "169.254.169.254"},
		{address: "127.0.0.1"},
		{address: "64:ff9b::a14:105"},
		{address: "64:ff9b:1::1"},
		{address: "2002:a14:105::1"},
		{address: "2001:0:a14:105::1"},
		{address: "::a14:105"},
		{address: "::ffff:10.20.1.5", valid: true},
		{address: "8.8.8.8", valid: true},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			address := netip.MustParseAddr(test.address)
			if got := validOutboundIP(address.Unmap(), allowed); got != test.valid {
				t.Fatalf("validOutboundIP(%s) = %t, want %t", test.address, got, test.valid)
			}
		})
	}
}

func TestOutboundClientAllowsExactHostPortAndPinnedUserInfo(t *testing.T) {
	issuer := "https://sso.example.test:8443/realms/corp"
	endpoints := genericTestEndpoints(issuer)
	endpoints.UserInfoURL = issuer + "/protocol/openid-connect/userinfo"
	client, transport, err := newOIDCOutboundHTTPClient(endpoints, outboundConnectorPolicy{
		caPEM: testCAPEM(t), privateNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	})
	if err != nil || client == nil {
		t.Fatalf("newOIDCOutboundHTTPClient() error = %v", err)
	}
	defer transport.CloseIdleConnections()
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("connector CA not in the root pool")
	}
	if _, _, err := newOIDCOutboundHTTPClient(endpoints, outboundConnectorPolicy{caPEM: []byte("junk")}); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("junk CA error = %v", err)
	}
	if _, _, err := newOIDCOutboundHTTPClient(endpoints, outboundConnectorPolicy{
		privateNetworks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("wide network error = %v", err)
	}
}

func TestSecureOutboundDialerMatchesHostAndPort(t *testing.T) {
	dialer := &secureOutboundDialer{
		resolver:        outboundResolverStub{addresses: []netip.Addr{netip.MustParseAddr("10.20.1.5")}},
		dial:            nil,
		allowedHosts:    map[string]struct{}{"sso.example.test:8443": {}},
		privateNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	}
	for _, address := range []string{"sso.example.test:443", "sso.example.test:22", "other.example.test:8443"} {
		if _, err := dialer.dialContext(t.Context(), "tcp", address); !errors.Is(err, errOutboundHTTPPolicy) {
			t.Fatalf("dialContext(%s) error = %v", address, err)
		}
	}
}
