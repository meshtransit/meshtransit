package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestLoadControlMTCPConfig(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		values  map[string]string
		wantErr string
	}{
		{name: "needs a key expiry", values: map[string]string{}, wantErr: envControlMTCPKeyNotAfter},
		{name: "cannot be turned off", values: map[string]string{
			envControlMTCPEnabled: "false", envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z",
		}, wantErr: envControlMTCPEnabled},
		{name: "invalid flag", values: map[string]string{envControlMTCPEnabled: "yes"}, wantErr: envControlMTCPEnabled},
		{name: "on without the switch", values: map[string]string{
			envControlMTCPKeyNotAfter:    "2027-10-10T07:00:00+07:00",
			envControlMTCPTrustedProxies: "10.0.0.0/8,2001:db8::/32",
		}},
		{name: "expiry in the past", values: map[string]string{
			envControlMTCPEnabled: "true", envControlMTCPKeyNotAfter: "2026-10-09T00:00:00Z",
		}, wantErr: envControlMTCPKeyNotAfter},
		{name: "expiry too far", values: map[string]string{
			envControlMTCPEnabled: "true", envControlMTCPKeyNotAfter: "2036-10-10T00:00:00Z",
		}, wantErr: envControlMTCPKeyNotAfter},
		{name: "bad proxy", values: map[string]string{
			envControlMTCPEnabled: "true", envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z",
			envControlMTCPTrustedProxies: "10.0.0.1/8",
		}, wantErr: envControlMTCPTrustedProxies},
		{name: "on", values: map[string]string{
			envControlMTCPEnabled: "true", envControlMTCPKeyNotAfter: "2027-10-10T07:00:00+07:00",
			envControlMTCPTrustedProxies: "10.0.0.0/8,2001:db8::/32",
		}},
		{name: "denied endpoints", values: map[string]string{
			envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z", envControlMTCPTrustedProxies: "10.0.0.0/8,2001:db8::/32",
			envControlMTCPDeniedEndpoints: "203.0.113.10/32,2001:db8:1::/48",
		}},
		{name: "denied endpoints not canonical", values: map[string]string{
			envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z", envControlMTCPDeniedEndpoints: "203.0.113.10/24",
		}, wantErr: envControlMTCPDeniedEndpoints},
		{name: "denied endpoints cover everything", values: map[string]string{
			envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z", envControlMTCPDeniedEndpoints: "203.0.113.10/32,::/0",
		}, wantErr: envControlMTCPDeniedEndpoints},
		{name: "denied endpoints mapped", values: map[string]string{
			envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z", envControlMTCPDeniedEndpoints: "::ffff:203.0.113.0/120",
		}, wantErr: envControlMTCPDeniedEndpoints},
		{name: "denied endpoints repeated", values: map[string]string{
			envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z", envControlMTCPDeniedEndpoints: "203.0.113.10/32,203.0.113.10/32",
		}, wantErr: envControlMTCPDeniedEndpoints},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := loadControlMTCPConfig(mapLookup(test.values), now, false)
			if test.wantErr != "" {
				if err == nil || !strings.HasSuffix(err.Error(), ": "+test.wantErr) {
					t.Fatalf("error = %v, want one naming %s", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !got.KeyNotAfter.Equal(time.Date(2027, 10, 10, 0, 0, 0, 0, time.UTC)) ||
				got.KeyNotAfter.Location() != time.UTC {
				t.Fatalf("KeyNotAfter = %v", got.KeyNotAfter)
			}
			proxies := got.TrustedProxyPrefixes()
			if len(proxies) != 2 || proxies[0] != netip.MustParsePrefix("10.0.0.0/8") {
				t.Fatalf("proxies = %v", proxies)
			}
			proxies[0] = netip.Prefix{}
			if got.TrustedProxyPrefixes()[0] != netip.MustParsePrefix("10.0.0.0/8") {
				t.Fatal("TrustedProxyPrefixes returned internal state")
			}
			denied := got.DeniedEndpointPrefixes()
			if value := test.values[envControlMTCPDeniedEndpoints]; value == "" && len(denied) != 0 ||
				value != "" && (len(denied) != 2 || denied[0] != netip.MustParsePrefix("203.0.113.10/32")) {
				t.Fatalf("denied endpoints = %v", denied)
			}
		})
	}
}

func TestLoadControlMTCPHandshakeLimits(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	base := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z"}
	got, err := loadControlMTCPConfig(mapLookup(base), now, false)
	if err != nil || got.HandshakeRate != 10 || got.HandshakeBurst != 50 {
		t.Fatalf("defaults = %d/%d, %v; want 10/50", got.HandshakeRate, got.HandshakeBurst, err)
	}
	raised := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z",
		envControlMTCPHandshakeRate: "100", envControlMTCPHandshakeBurst: "2000"}
	if got, err := loadControlMTCPConfig(mapLookup(raised), now, false); err != nil ||
		got.HandshakeRate != 100 || got.HandshakeBurst != 2000 {
		t.Fatalf("raised = %d/%d, %v", got.HandshakeRate, got.HandshakeBurst, err)
	}
	for name, value := range map[string]string{
		envControlMTCPHandshakeRate: "0", envControlMTCPHandshakeBurst: "100001",
	} {
		values := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z", name: value}
		if _, err := loadControlMTCPConfig(mapLookup(values), now, false); err == nil || !strings.HasSuffix(err.Error(), ": "+name) {
			t.Errorf("%s=%s accepted: %v", name, value, err)
		}
	}
	// A burst below the rate would refuse a whole second's allowance.
	low := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z",
		envControlMTCPHandshakeRate: "100", envControlMTCPHandshakeBurst: "50"}
	if _, err := loadControlMTCPConfig(mapLookup(low), now, false); err == nil {
		t.Error("burst below the rate accepted")
	}
}

func TestLoadControlMTCPUnauthenticatedLimits(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	base := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z"}
	got, err := loadControlMTCPConfig(mapLookup(base), now, false)
	if err != nil || got.UnauthenticatedPerSource != 150 || got.UnprovenLifetime != 15*time.Minute {
		t.Fatalf("defaults = %d/%s, %v; want 150/15m", got.UnauthenticatedPerSource, got.UnprovenLifetime, err)
	}
	// The default follows raised handshake limits, up to its maximum.
	for _, test := range []struct {
		rate, burst string
		want        int
	}{{"100", "200", 200 + 100*10}, {"2000", "20000", 10000}} {
		values := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z",
			envControlMTCPHandshakeRate: test.rate, envControlMTCPHandshakeBurst: test.burst}
		if got, err := loadControlMTCPConfig(mapLookup(values), now, false); err != nil ||
			got.UnauthenticatedPerSource != test.want {
			t.Errorf("rate %s burst %s: unauthenticated = %d, %v; want %d", test.rate, test.burst,
				got.UnauthenticatedPerSource, err, test.want)
		}
	}
	raised := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z",
		envControlMTCPUnauthenticatedPerSource: "500", envControlMTCPUnprovenLifetime: "1h"}
	if got, err := loadControlMTCPConfig(mapLookup(raised), now, false); err != nil ||
		got.UnauthenticatedPerSource != 500 || got.UnprovenLifetime != time.Hour {
		t.Fatalf("raised = %d/%s, %v", got.UnauthenticatedPerSource, got.UnprovenLifetime, err)
	}
	for _, test := range []struct{ name, value string }{
		{envControlMTCPUnauthenticatedPerSource, "0"},
		{envControlMTCPUnauthenticatedPerSource, "10001"},
		{envControlMTCPUnauthenticatedPerSource, "many"},
		// Shorter than a browser approval would cut registrations off.
		{envControlMTCPUnprovenLifetime, "10m"},
		{envControlMTCPUnprovenLifetime, "25h"},
		{envControlMTCPUnprovenLifetime, "900"},
	} {
		values := map[string]string{envControlMTCPKeyNotAfter: "2027-10-10T00:00:00Z", test.name: test.value}
		if _, err := loadControlMTCPConfig(mapLookup(values), now, false); err == nil ||
			!strings.HasSuffix(err.Error(), ": "+test.name) || strings.Contains(err.Error(), test.value) {
			t.Errorf("%s=%s: %v", test.name, test.value, err)
		}
	}
}

func TestLoadControlMTCPNextKeyExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	values := map[string]string{
		envControlMTCPKeyNotAfter:     "2027-10-10T00:00:00Z",
		envControlMTCPNextKeyNotAfter: "2028-10-10T00:00:00Z",
	}
	got, err := loadControlMTCPConfig(mapLookup(values), now, true)
	if err != nil || !got.NextKeyNotAfter.Equal(time.Date(2028, 10, 10, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("next key expiry = %v, %v", got.NextKeyNotAfter, err)
	}
	// The expiry and the next key file come together or not at all.
	if _, err := loadControlMTCPConfig(mapLookup(values), now, false); err == nil {
		t.Error("next key expiry accepted without a next key")
	}
	delete(values, envControlMTCPNextKeyNotAfter)
	if _, err := loadControlMTCPConfig(mapLookup(values), now, true); err == nil {
		t.Error("next key accepted without an expiry")
	}
	values[envControlMTCPNextKeyNotAfter] = "2026-10-09T00:00:00Z"
	if _, err := loadControlMTCPConfig(mapLookup(values), now, true); err == nil {
		t.Error("past next key expiry accepted")
	}
}
