package main

import (
	"strings"
	"testing"
)

const (
	qualificationDeployment = "01960000-0000-7000-8000-000000000001"
	qualificationWorkspace  = "01960000-0000-7000-8000-000000000002"
	qualificationOwner      = "01960000-0000-7000-8000-000000000003"
)

func TestParsePlanRejectsUnsafeInputs(t *testing.T) {
	cases := []struct{ name, deployment, label, ipv4, ipv6 string }{
		{"invalid scope", "not-an-id", "Qualification", "100.64.20.0/24", "fd00:20::/64"},
		{"blank name", qualificationDeployment, " ", "100.64.20.0/24", "fd00:20::/64"},
		{"control in name", qualificationDeployment, "Qualification\tNetwork", "100.64.20.0/24", "fd00:20::/64"},
		{"invalid UTF-8", qualificationDeployment, string([]byte{0xff}), "100.64.20.0/24", "fd00:20::/64"},
		{"long name", qualificationDeployment, strings.Repeat("n", 81), "100.64.20.0/24", "fd00:20::/64"},
		{"IPv4 host bits", qualificationDeployment, "Qualification", "100.64.20.1/24", "fd00:20::/64"},
		{"IPv4 broad prefix", qualificationDeployment, "Qualification", "100.64.0.0/16", "fd00:20::/64"},
		{"IPv4 family swap", qualificationDeployment, "Qualification", "fd00:21::/64", "fd00:20::/64"},
		{"IPv6 host bits", qualificationDeployment, "Qualification", "100.64.20.0/24", "fd00:20::1/64"},
		{"IPv6 broad prefix", qualificationDeployment, "Qualification", "100.64.20.0/24", "fd00:20::/48"},
		{"mapped IPv4", qualificationDeployment, "Qualification", "100.64.20.0/24", "::ffff:100.64.20.0/120"},
		{"link local", qualificationDeployment, "Qualification", "100.64.20.0/24", "fe80::/64"},
		{"multicast", qualificationDeployment, "Qualification", "100.64.20.0/24", "ff00::/64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePlan(tc.deployment, qualificationWorkspace, qualificationOwner, tc.label, tc.ipv4, tc.ipv6, true); err == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
}

func TestParsePlanAcceptsCanonicalDualStackScope(t *testing.T) {
	p, err := parsePlan(qualificationDeployment, qualificationWorkspace, qualificationOwner, " Qualification Network ", "100.64.20.0/24", "fd00:20::/64", false)
	if err != nil {
		t.Fatal(err)
	}
	if p.apply || p.name != "Qualification Network" || len(p.prefixes) != 2 || !p.prefixes[0].Addr().Is4() || !p.prefixes[1].Addr().Is6() {
		t.Fatalf("unexpected scoped plan: %+v", p)
	}
}

func FuzzParsePlan(f *testing.F) {
	f.Add("Qualification", "100.64.20.0/24", "fd00:20::/64")
	f.Add("Unsafe\x00name", "100.64.20.1/24", "::ffff:100.64.20.0/120")
	f.Fuzz(func(t *testing.T, name, ipv4, ipv6 string) {
		p, err := parsePlan(qualificationDeployment, qualificationWorkspace, qualificationOwner, name, ipv4, ipv6, false)
		if err != nil {
			return
		}
		if len(p.prefixes) != 2 || p.prefixes[0] != p.prefixes[0].Masked() || p.prefixes[1] != p.prefixes[1].Masked() || p.prefixes[0].Addr().Is4() == p.prefixes[1].Addr().Is4() {
			t.Fatal("accepted noncanonical or single-family plan")
		}
	})
}
