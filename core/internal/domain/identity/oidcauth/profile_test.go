package oidcauth

import (
	"strings"
	"testing"
)

func TestProfileKeepsOnlyBoundedDisplayData(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, inName, inEmail, wantName, wantEmail, display string
	}{
		{"both", "  Lan Tran ", "lan@example.com", "Lan Tran", "lan@example.com", "Lan Tran"},
		{"email only", "", "lan@example.com", "", "lan@example.com", "lan@example.com"},
		{"neither", "", "", "", "", "fallback"},
		{"control character", "Lan\nTran", "lan@example.com", "", "lan@example.com", "lan@example.com"},
		{"long name", strings.Repeat("a", maximumProfileNameRunes+1), "", "", "", "fallback"},
		{"not an email", "Lan", "lan.example.com", "Lan", "", "Lan"},
		{"two at signs", "Lan", "lan@x@example.com", "Lan", "", "Lan"},
		{"display form", "Lan", "Lan <lan@example.com>", "Lan", "", "Lan"},
		{"line separator", "Lan Tran", "", "", "", "fallback"},
	} {
		profile := NewProfile(test.inName, test.inEmail)
		if profile.Name() != test.wantName || profile.Email() != test.wantEmail ||
			profile.DisplayName("fallback") != test.display {
			t.Errorf("%s: profile = %q %q %q", test.name, profile.Name(), profile.Email(), profile.DisplayName("fallback"))
		}
	}
	if NewProfile("Lan", "lan@example.com").String() != "[REDACTED]" {
		t.Error("profile must redact")
	}
}
