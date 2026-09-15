package network_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/network"
)

func TestParseDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{name: "ascii", value: "Development Mesh"},
		{name: "unicode", value: "Mạng phát triển"},
		{name: "empty", wantError: true},
		{name: "leading whitespace", value: " Development Mesh", wantError: true},
		{name: "trailing whitespace", value: "Development Mesh ", wantError: true},
		{name: "control character", value: "Development\nMesh", wantError: true},
		{name: "too long", value: strings.Repeat("a", 129), wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			name, err := network.ParseDisplayName(test.value)
			if test.wantError {
				if !errors.Is(err, network.ErrInvalidDisplayName) {
					t.Fatalf("ParseDisplayName() error = %v, want ErrInvalidDisplayName", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDisplayName() error = %v", err)
			}
			if name.String() != test.value || !name.IsValid() {
				t.Fatalf("ParseDisplayName() = %q, want valid %q", name.String(), test.value)
			}
		})
	}

	if (network.DisplayName{}).IsValid() {
		t.Fatal("zero DisplayName is valid")
	}
}
