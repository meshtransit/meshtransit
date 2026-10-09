package enrollment_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
)

const testCredentialPresentation = "mtc1.01890f90-0000-7000-8000-000000000001." +
	"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

func TestCredentialPresentationCanonicalEncoding(t *testing.T) {
	t.Parallel()

	id, token := credentialPresentationParts(t)
	presentation, err := enrollment.NewCredentialPresentation(id, token)
	if err != nil {
		t.Fatalf("NewCredentialPresentation() error = %v", err)
	}
	if presentation.Reveal() != testCredentialPresentation {
		t.Fatalf("CredentialPresentation.Reveal() = %q, want canonical encoding", presentation.Reveal())
	}
	parsed, err := enrollment.ParseCredentialPresentation(testCredentialPresentation)
	if err != nil {
		t.Fatalf("ParseCredentialPresentation() error = %v", err)
	}
	if parsed != presentation || parsed.CredentialID() != id || parsed.Token() != token {
		t.Fatal("ParseCredentialPresentation() changed credential semantics")
	}
}

func TestCredentialPresentationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	id, token := credentialPresentationParts(t)
	validID := id.String()
	validToken := token.Reveal()
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "wrong prefix", value: "mtc2." + validID + "." + validToken},
		{name: "uppercase prefix", value: "MTC1." + validID + "." + validToken},
		{name: "missing id", value: "mtc1.." + validToken},
		{name: "invalid id", value: "mtc1.invalid." + validToken},
		{name: "uppercase id", value: "mtc1." + strings.ToUpper(validID) + "." + validToken},
		{name: "missing token", value: "mtc1." + validID + "."},
		{name: "padded token", value: "mtc1." + validID + "." + validToken + "="},
		{name: "extra segment", value: testCredentialPresentation + ".extra"},
		{name: "leading whitespace", value: " " + testCredentialPresentation},
		{name: "trailing newline", value: testCredentialPresentation + "\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := enrollment.ParseCredentialPresentation(test.value)
			if !errors.Is(err, enrollment.ErrInvalidCredentialPresentation) {
				t.Fatalf("ParseCredentialPresentation() error = %v, want invalid presentation", err)
			}
			if test.value != "" && err != nil && strings.Contains(err.Error(), test.value) {
				t.Fatal("ParseCredentialPresentation() error disclosed rejected bearer input")
			}
		})
	}

	if _, err := enrollment.NewCredentialPresentation(enrollment.CredentialID{}, token); !errors.Is(
		err,
		enrollment.ErrInvalidCredentialPresentation,
	) {
		t.Fatalf("NewCredentialPresentation(zero id) error = %v, want invalid presentation", err)
	}
	if _, err := enrollment.NewCredentialPresentation(id, enrollment.CredentialToken{}); !errors.Is(
		err,
		enrollment.ErrInvalidCredentialPresentation,
	) {
		t.Fatalf("NewCredentialPresentation(zero token) error = %v, want invalid presentation", err)
	}
	if (enrollment.CredentialPresentation{}).IsValid() {
		t.Fatal("zero CredentialPresentation is valid")
	}
}

func TestCredentialPresentationFormattingIsRedacted(t *testing.T) {
	t.Parallel()

	presentation, err := enrollment.ParseCredentialPresentation(testCredentialPresentation)
	if err != nil {
		t.Fatalf("ParseCredentialPresentation() error = %v", err)
	}
	formatted := []string{
		fmt.Sprint(presentation),
		fmt.Sprintf("%#v", presentation),
		presentation.LogValue().String(),
	}
	for _, value := range formatted {
		if strings.Contains(value, presentation.Token().Reveal()) || value == testCredentialPresentation {
			t.Fatalf("credential presentation formatting disclosed bearer proof: %q", value)
		}
	}
	if formatted[0] != "[REDACTED]" ||
		formatted[1] != "enrollment.CredentialPresentation([REDACTED])" ||
		formatted[2] != "[REDACTED]" {
		t.Fatalf("credential presentation redaction = %q", formatted)
	}
}

func FuzzParseCredentialPresentation(f *testing.F) {
	f.Add(testCredentialPresentation)
	f.Add("")
	f.Add("mtc1.invalid.invalid")

	f.Fuzz(func(t *testing.T, encoded string) {
		presentation, err := enrollment.ParseCredentialPresentation(encoded)
		if err != nil {
			return
		}
		if !presentation.IsValid() || presentation.Reveal() != encoded {
			t.Fatal("ParseCredentialPresentation() accepted a non-canonical presentation")
		}
	})
}

func credentialPresentationParts(t *testing.T) (enrollment.CredentialID, enrollment.CredentialToken) {
	t.Helper()

	id, err := enrollment.ParseCredentialID("01890f90-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("ParseCredentialID() error = %v", err)
	}
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	token, err := enrollment.NewCredentialToken(secret)
	if err != nil {
		t.Fatalf("NewCredentialToken() error = %v", err)
	}
	return id, token
}
