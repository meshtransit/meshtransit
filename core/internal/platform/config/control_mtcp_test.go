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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := loadControlMTCPConfig(mapLookup(test.values), now)
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
		})
	}
}
