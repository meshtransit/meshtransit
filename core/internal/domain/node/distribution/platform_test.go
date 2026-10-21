package distribution

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIsPublicAddress(t *testing.T) {
	for text, want := range map[string]bool{
		"203.0.113.7": true, "8.8.8.8": true, "2a01:4f8::1": true,
		"10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false, "100.64.1.1": false,
		"100.127.255.254": false, "127.0.0.1": false, "169.254.1.1": false, "fe80::1": false,
		"fd00::1": false, "::1": false, "0.0.0.0": false, "224.0.0.1": false, "::ffff:8.8.8.8": false,
	} {
		if got := IsPublicAddress(netip.MustParseAddr(text)); got != want {
			t.Errorf("IsPublicAddress(%s) = %v, want %v", text, got, want)
		}
	}
	if IsPublicAddress(netip.Addr{}) {
		t.Error("the zero address is public")
	}
}

func TestConnectivityPublicAddresses(t *testing.T) {
	now := time.Now()
	addresses := func(texts ...string) []netip.Addr {
		values := make([]netip.Addr, 0, len(texts))
		for _, text := range texts {
			values = append(values, netip.MustParseAddr(text))
		}
		return values
	}
	for name, test := range map[string]struct {
		addresses []netip.Addr
		valid     bool
	}{
		"none":        {nil, true},
		"ordered":     {addresses("8.8.8.8", "203.0.113.7", "2a01:4f8::1"), true},
		"four":        {addresses("1.1.1.1", "8.8.8.8", "2a01:4f8::1", "2a01:4f8::2"), true},
		"five":        {addresses("1.1.1.1", "8.8.8.8", "9.9.9.9", "2a01:4f8::1", "2a01:4f8::2"), false},
		"unordered":   {addresses("203.0.113.7", "8.8.8.8"), false},
		"duplicate":   {addresses("8.8.8.8", "8.8.8.8"), false},
		"private":     {addresses("10.0.0.1"), false},
		"v6 before 4": {addresses("2a01:4f8::1", "8.8.8.8"), false},
	} {
		report := Connectivity{ReportedAt: now, PublicAddresses: test.addresses}
		if got := report.IsValid(); got != test.valid {
			t.Errorf("%s: IsValid = %v, want %v", name, got, test.valid)
		}
	}
	one := Connectivity{ReportedAt: now, PublicAddresses: addresses("8.8.8.8")}
	other := Connectivity{ReportedAt: now.Add(time.Minute), PublicAddresses: addresses("1.1.1.1")}
	if one.SameAs(other) || !one.SameAs(Connectivity{ReportedAt: now, PublicAddresses: addresses("8.8.8.8")}) {
		t.Error("SameAs does not compare public addresses")
	}
}

func TestPlatformIsValid(t *testing.T) {
	for name, test := range map[string]struct {
		platform Platform
		valid    bool
	}{
		"full":         {Platform{OS: "darwin", OSVersion: "15.5", Arch: "arm64", ClientVersion: "0.9.1"}, true},
		"os only":      {Platform{OS: "linux"}, true},
		"no os":        {Platform{Arch: "amd64"}, false},
		"long":         {Platform{OS: strings.Repeat("x", maximumPlatformField+1)}, false},
		"control":      {Platform{OS: "linux", OSVersion: "1\n2"}, false},
		"invalid utf8": {Platform{OS: "linux", Arch: "\xff"}, false},
	} {
		if got := test.platform.IsValid(); got != test.valid {
			t.Errorf("%s: IsValid = %v, want %v", name, got, test.valid)
		}
	}
}
