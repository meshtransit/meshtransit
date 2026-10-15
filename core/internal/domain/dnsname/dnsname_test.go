package dnsname

import (
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/node"
)

// longestSuffix is a valid suffix of exactly MaximumSuffixBytes.
var longestSuffix = strings.Repeat(strings.Repeat("a", 51)+".", 3)[:MaximumSuffixBytes]

func TestParseSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "default", value: "mesh.internal", want: "mesh.internal"},
		{name: "single label", value: "mesh", want: "mesh"},
		{name: "lowercased", value: "Corp.Example", want: "corp.example"},
		{name: "longest", value: longestSuffix, want: longestSuffix},
		{name: "too long", value: longestSuffix + "a"},
		{name: "empty", value: ""},
		{name: "trailing dot", value: "mesh.internal."},
		{name: "leading dot", value: ".mesh"},
		{name: "empty label", value: "mesh..internal"},
		{name: "space", value: " mesh"},
		{name: "underscore", value: "my_mesh"},
		{name: "numeric last label", value: "mesh.123"},
		{name: "address", value: "192.0.2.1"},
		{name: "hyphen edge", value: "mesh-.internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			suffix, err := ParseSuffix(test.value)
			if test.want == "" {
				if err == nil {
					t.Fatalf("ParseSuffix(%q) = %q, want error", test.value, suffix)
				}
				return
			}
			if err != nil || suffix.String() != test.want || !suffix.IsValid() {
				t.Fatalf("ParseSuffix(%q) = %q, %v; want %q", test.value, suffix, err, test.want)
			}
		})
	}
	if !Default().IsValid() || Default().String() != DefaultSuffix {
		t.Fatalf("Default() = %q", Default())
	}
}

func TestZoneNamesDevicesWithinBounds(t *testing.T) {
	t.Parallel()
	workspace := must(identity.ParseDisplayCode("000000000101"))
	networkCode := must(identity.ParseDisplayCode("000000000202"))
	zone := must(NewZone(workspace, networkCode, Default()))
	if zone.String() != "000000000101.000000000202.mesh.internal" {
		t.Fatalf("zone = %q", zone)
	}
	name, ok := zone.DeviceName(must(node.ParseDNSLabel("laptop")))
	if !ok || name != "laptop.000000000101.000000000202.mesh.internal" {
		t.Fatalf("DeviceName = %q, %v", name, ok)
	}
	if !zone.Contains(name) || zone.Contains("laptop.000000000101.000000000203.mesh.internal") ||
		zone.Contains("x"+zone.String()) {
		t.Fatal("Contains is not exact")
	}
	if _, ok := zone.DeviceName(node.DNSLabel{}); ok {
		t.Fatal("an invalid label must not be named")
	}
	if _, err := NewZone("", networkCode, Default()); err == nil {
		t.Fatal("a zone needs both codes")
	}
	longZone := must(NewZone(workspace, networkCode, must(ParseSuffix(longestSuffix))))
	longName, ok := longZone.DeviceName(must(node.ParseDNSLabel(strings.Repeat("b", 63))))
	if !ok || len(longName)+1 > 253 {
		t.Fatalf("longest Device name is %d bytes with its root dot", len(longName)+1)
	}
}

func TestSharedNameMovesUnderSuffix(t *testing.T) {
	t.Parallel()
	label := strings.Repeat("c", 63)
	longest := must(ParseSuffix(longestSuffix))
	tests := []struct {
		name   string
		suffix Suffix
		stored string
		want   string
	}{
		{name: "default", suffix: Default(), stored: "db.000000000101.000000000202.shared.mesh",
			want: "db.000000000101.000000000202.shared.mesh.internal"},
		{name: "suffix mesh keeps the name", suffix: must(ParseSuffix("mesh")),
			stored: "db.000000000101.000000000202.shared.mesh", want: "db.000000000101.000000000202.shared.mesh"},
		{name: "legacy typed name", suffix: Default(), stored: "db.corp.example", want: "db.corp.example"},
		{name: "not the shared zone", suffix: Default(), stored: "db.notshared.mesh", want: "db.notshared.mesh"},
		{name: "longest", suffix: longest, stored: label + ".000000000101.000000000202.shared.mesh",
			want: label + ".000000000101.000000000202.shared." + longest.String()},
		{name: "too long stays", suffix: longest, stored: label + ".x" + label + ".000000000101.000000000202.shared.mesh",
			want: label + ".x" + label + ".000000000101.000000000202.shared.mesh"},
		{name: "invalid suffix", suffix: Suffix{}, stored: "db.000000000101.000000000202.shared.mesh",
			want: "db.000000000101.000000000202.shared.mesh"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := test.suffix.SharedName(test.stored)
			if got != test.want {
				t.Fatalf("SharedName(%q) = %q, want %q", test.stored, got, test.want)
			}
			if len(got)+1 > 253 {
				t.Fatalf("SharedName(%q) is %d bytes with its root dot", test.stored, len(got)+1)
			}
			if test.suffix.IsValid() && test.suffix.StoredSharedName(got) != test.stored {
				t.Fatalf("StoredSharedName(%q) = %q, want %q", got, test.suffix.StoredSharedName(got), test.stored)
			}
		})
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
