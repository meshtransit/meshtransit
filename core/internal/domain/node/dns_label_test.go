package node

import (
	"strings"
	"testing"
)

func TestParseDNSLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "simple", value: "laptop", valid: true},
		{name: "hyphen and digits", value: "build-01", valid: true},
		{name: "longest", value: strings.Repeat("a", 63), valid: true},
		{name: "too long", value: strings.Repeat("a", 64)},
		{name: "empty", value: ""},
		{name: "uppercase", value: "Laptop"},
		{name: "two labels", value: "laptop.example"},
		{name: "leading hyphen", value: "-laptop"},
		{name: "trailing hyphen", value: "laptop-"},
		{name: "underscore", value: "my_laptop"},
		{name: "all digits", value: "1234"},
		{name: "non ascii", value: "läptop"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			label, err := ParseDNSLabel(test.value)
			if (err == nil) != test.valid {
				t.Fatalf("ParseDNSLabel(%q) error = %v, valid %v", test.value, err, test.valid)
			}
			if test.valid && (label.String() != test.value || !label.IsValid()) {
				t.Fatalf("ParseDNSLabel(%q) = %q", test.value, label)
			}
		})
	}
	if (DNSLabel{}).IsValid() {
		t.Fatal("zero DNSLabel must be invalid")
	}
}
