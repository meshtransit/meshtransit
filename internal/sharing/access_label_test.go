package sharing_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/sharing"
)

func TestParseAccessLabel(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name, value, want string
		valid             bool
	}{
		{name: "simple", value: "poc01", want: "poc01", valid: true},
		{name: "uppercase canonicalizes", value: "Db-Primary", want: "db-primary", valid: true},
		{name: "single character", value: "a", want: "a", valid: true},
		{name: "maximum length", value: strings.Repeat("a", 63), want: strings.Repeat("a", 63), valid: true},
		{name: "empty", value: ""},
		{name: "too long", value: strings.Repeat("a", 64)},
		{name: "dot", value: "a.b"},
		{name: "leading hyphen", value: "-a"},
		{name: "trailing hyphen", value: "a-"},
		{name: "underscore", value: "a_b"},
		{name: "all digits", value: "0123"},
		{name: "space", value: " poc01"},
		{name: "unicode", value: "pôc"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			label, err := sharing.ParseAccessLabel(testCase.value)
			if !testCase.valid {
				if !errors.Is(err, sharing.ErrInvalidAccessLabel) || label.IsValid() {
					t.Fatalf("ParseAccessLabel(%q) = %q, %v; want invalid", testCase.value, label, err)
				}
				return
			}
			if err != nil || label.String() != testCase.want || !label.IsValid() {
				t.Fatalf("ParseAccessLabel(%q) = %q, %v; want %q", testCase.value, label, err, testCase.want)
			}
		})
	}
}

func TestDefaultAccessLabel(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct{ hostname, want string }{
		{hostname: "poc-01-2", want: "poc-01-2"},
		{hostname: "DB_Primary.example.internal", want: "db-primary"},
		{hostname: "  web server 01  ", want: "web-server-01"},
		{hostname: "---edge---", want: "edge"},
		{hostname: "12345", want: "device-12345"},
		{hostname: "", want: "device"},
		{hostname: "日本", want: "device"},
		{hostname: strings.Repeat("ab", 40), want: strings.Repeat("ab", 31) + "a"},
		{hostname: strings.Repeat("7", 70) + "x", want: "device-" + strings.Repeat("7", 56)},
		{hostname: strings.Repeat("a", 62) + "-b", want: strings.Repeat("a", 62)},
	} {
		label := sharing.DefaultAccessLabel(testCase.hostname)
		if label.String() != testCase.want || !label.IsValid() {
			t.Errorf("DefaultAccessLabel(%q) = %q, want valid %q", testCase.hostname, label, testCase.want)
		}
	}
}
