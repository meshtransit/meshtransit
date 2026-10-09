package identity_test

import (
	"testing"

	"meshtransit.net/core/internal/domain/identity"
)

func TestDisplayCode(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		input string
		valid bool
	}{
		{name: "twelve digits", input: "123456789012", valid: true},
		{name: "leading zeros", input: "001234567890", valid: true},
		{name: "short", input: "12345678901"},
		{name: "long", input: "1234567890123"},
		{name: "space", input: " 123456789012"},
		{name: "letters", input: "12345678901a"},
		{name: "unicode digits", input: "１２３４５６７８９０１２"},
		{name: "empty"},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, err := identity.ParseDisplayCode(test.input)
			if test.valid {
				if err != nil || !code.IsValid() || code.String() != test.input {
					t.Fatalf("valid code did not round trip: %v", err)
				}
			} else if err == nil || code.IsValid() {
				t.Fatal("malformed display code accepted")
			}
		})
	}
}
