package enrollment_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
)

func filledToken(t *testing.T, value byte) enrollment.CredentialToken {
	t.Helper()
	token, err := enrollment.NewCredentialToken([32]byte(bytes.Repeat([]byte{value}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestJoinKeyPresentationRoundTripAndRedaction(t *testing.T) {
	t.Parallel()
	id := mustCredentialID(t)
	token := filledToken(t, 0x42)
	presentation, err := enrollment.NewJoinKeyPresentation(id, token)
	if err != nil {
		t.Fatalf("enrollment.NewJoinKeyPresentation() error = %v", err)
	}
	encoded := presentation.Reveal()
	if !strings.HasPrefix(encoded, "mtk1.") {
		t.Fatalf("Reveal() = %q, want the mtk1 prefix", encoded)
	}
	parsed, err := enrollment.ParseJoinKeyPresentation(encoded)
	if err != nil || parsed.CredentialID() != id || parsed.Token() != token {
		t.Fatalf("enrollment.ParseJoinKeyPresentation() = %v, %v", parsed, err)
	}
	for _, rendered := range []string{fmt.Sprint(presentation), fmt.Sprintf("%#v", presentation),
		presentation.LogValue().String()} {
		if strings.Contains(rendered, token.Reveal()) {
			t.Fatalf("a join key rendered its secret: %q", rendered)
		}
	}
}

// A join key is never an enrollment key and an enrollment key never a join
// key: each parser refuses the other's prefix.
func TestJoinKeyAndEnrollmentKeyPrefixesDoNotMix(t *testing.T) {
	t.Parallel()
	id := mustCredentialID(t)
	token := filledToken(t, 0x43)
	join, err := enrollment.NewJoinKeyPresentation(id, token)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentKey, err := enrollment.NewCredentialPresentation(id, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.ParseCredentialPresentation(join.Reveal()); !errors.Is(err, enrollment.ErrInvalidCredentialPresentation) {
		t.Fatalf("enrollment.ParseCredentialPresentation(join key) error = %v", err)
	}
	if _, err := enrollment.ParseJoinKeyPresentation(enrollmentKey.Reveal()); !errors.Is(err, enrollment.ErrInvalidCredentialPresentation) {
		t.Fatalf("enrollment.ParseJoinKeyPresentation(enrollment key) error = %v", err)
	}
	for _, encoded := range []string{"", "mtk1.", "mtk1." + id.String(), "mtk2." + id.String() + "." + token.Reveal()} {
		if _, err := enrollment.ParseJoinKeyPresentation(encoded); !errors.Is(err, enrollment.ErrInvalidCredentialPresentation) {
			t.Errorf("enrollment.ParseJoinKeyPresentation(%q) error = %v", encoded, err)
		}
	}
}

func FuzzParseJoinKeyPresentation(f *testing.F) {
	f.Add("mtk1.01890f00-0000-7000-8000-000000000402.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI")
	f.Add("mtc1.x.y")
	f.Add("")
	f.Fuzz(func(t *testing.T, encoded string) {
		presentation, err := enrollment.ParseJoinKeyPresentation(encoded)
		if err != nil {
			return
		}
		if presentation.Reveal() != encoded {
			t.Fatalf("ParseJoinKeyPresentation(%q) does not round-trip: %q", encoded, presentation.Reveal())
		}
		if _, err := enrollment.ParseCredentialPresentation(encoded); err == nil {
			t.Fatalf("%q parsed as both a join key and an enrollment key", encoded)
		}
	})
}
