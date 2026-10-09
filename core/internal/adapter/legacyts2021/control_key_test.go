package legacyts2021

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

func TestParseControlPrivateKeyAcceptsCanonicalMaterial(t *testing.T) {
	t.Parallel()

	privateKey, encoded := newControlPrivateKeyFixture(t)
	if !privateKey.IsValid() {
		t.Fatal("ParseControlPrivateKey() returned invalid key")
	}
	for _, rendered := range []string{
		fmt.Sprint(privateKey),
		fmt.Sprintf("%#v", privateKey),
		privateKey.LogValue().String(),
	} {
		if strings.Contains(rendered, encoded) || rendered != "[REDACTED]" &&
			rendered != "legacyts2021.ControlPrivateKey([REDACTED])" {
			t.Fatalf("formatted private key = %q, want redacted", rendered)
		}
	}
}

func TestParseControlPrivateKeyRejectsUnsafeMaterial(t *testing.T) {
	t.Parallel()

	_, canonical := newControlPrivateKeyFixture(t)
	for _, encoded := range []string{
		"",
		"invalid",
		canonical + "\n",
		strings.ToUpper(canonical),
		"privkey:" + strings.Repeat("0", 64),
	} {
		if _, err := ParseControlPrivateKey(encoded); !errors.Is(err, ErrInvalidControlPrivateKey) {
			t.Fatalf("ParseControlPrivateKey(%q) error = %v, want invalid key", encoded, err)
		}
	}
}

func newControlPrivateKeyFixture(t testing.TB) (ControlPrivateKey, string) {
	t.Helper()

	generated := key.NewMachine()
	encoded, err := generated.MarshalText()
	if err != nil {
		t.Fatalf("MachinePrivate.MarshalText() error = %v", err)
	}
	privateKey, err := ParseControlPrivateKey(string(encoded))
	clear(encoded)
	if err != nil {
		t.Fatalf("ParseControlPrivateKey() error = %v", err)
	}
	canonical, err := generated.MarshalText()
	if err != nil {
		t.Fatalf("MachinePrivate.MarshalText() error = %v", err)
	}
	return privateKey, string(canonical)
}

var _ slog.LogValuer = ControlPrivateKey{}
