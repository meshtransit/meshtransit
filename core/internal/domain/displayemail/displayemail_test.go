package displayemail

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	t.Parallel()
	for email, want := range map[string]bool{
		"person@example.test":                 true,
		"a.b+c@example.test":                  true,
		"":                                    false,
		"a@b":                                 false,
		"no-at.example.test":                  false,
		"two@at@example.test":                 false,
		"@example.test":                       false,
		"user@":                               false,
		"user@localhost":                      false,
		"user@exämple.test":                   false,
		"user\u00a0x@example.test":            false,
		"user\u202e@example.test":             false,
		"user<x@example.test":                 false,
		"user>x@example.test":                 false,
		"user\"x@example.test":                false,
		"user x@example.test":                 false,
		"user\tx@example.test":                false,
		strings.Repeat("a", 240) + "@ex.test": true,
		strings.Repeat("a", 250) + "@ex.test": false,
	} {
		if got := Valid(email); got != want {
			t.Errorf("Valid(%q) = %t, want %t", email, got, want)
		}
	}
}
