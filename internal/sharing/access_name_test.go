package sharing

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAccessNameCanonicalizesDNSName(t *testing.T) {
	t.Parallel()

	name, err := ParseAccessName("Database-Primary.Shared.Consumer.Example")
	if err != nil {
		t.Fatalf("ParseAccessName() error = %v", err)
	}
	if name.String() != "database-primary.shared.consumer.example" || !name.IsValid() {
		t.Fatalf("ParseAccessName() = %q, want canonical name", name.String())
	}
}

func TestParseAccessNameRejectsUnsafeOrRelativeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "relative label", value: "database"},
		{name: "leading whitespace", value: " database.shared.example"},
		{name: "trailing root dot", value: "database.shared.example."},
		{name: "empty label", value: "database..example"},
		{name: "leading hyphen", value: "-database.shared.example"},
		{name: "trailing hyphen", value: "database-.shared.example"},
		{name: "underscore", value: "database_primary.shared.example"},
		{name: "unicode without IDNA", value: "dàtabase.shared.example"},
		{name: "IPv4 literal", value: "10.20.30.40"},
		{name: "numeric pseudo address", value: "999.999.999.999"},
		{name: "oversized label", value: strings.Repeat("a", 64) + ".example"},
		{name: "oversized name", value: strings.Repeat("a.", 126) + "aa"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			name, err := ParseAccessName(test.value)
			if !errors.Is(err, ErrInvalidAccessName) || name.IsValid() {
				t.Fatalf("ParseAccessName(%q) = %#v, %v; want invalid", test.value, name, err)
			}
		})
	}
}
