package config

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
)

func TestLoadDNSSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value *string
		want  string
	}{
		{name: "default", want: dnsname.DefaultSuffix},
		{name: "custom", value: pointer("corp.internal"), want: "corp.internal"},
		{name: "lowercased", value: pointer("Corp.Internal"), want: "corp.internal"},
		{name: "single label", value: pointer("mesh")},
		{name: "special use", value: pointer("mesh.local")},
		{name: "empty", value: pointer("")},
		{name: "trailing dot", value: pointer("corp.example.")},
		{name: "invalid label", value: pointer("corp_example")},
		{name: "numeric last label", value: pointer("corp.123")},
		{name: "too long", value: pointer(strings.Repeat("a.", 78) + "a")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(nil)
			if test.value != nil {
				values[envDNSSuffix] = *test.value
			}
			got, err := Load(mapLookup(values))
			if test.want == "" {
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envDNSSuffix) {
					t.Fatalf("Load() error = %v, want invalid %s", err, envDNSSuffix)
				}
				return
			}
			if err != nil || got.DNSSuffix.String() != test.want {
				t.Fatalf("Load() = %q, %v; want %q", got.DNSSuffix, err, test.want)
			}
		})
	}
}

func pointer(value string) *string { return &value }
