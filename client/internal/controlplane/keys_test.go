package controlplane

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func TestKeyText(t *testing.T) {
	t.Parallel()
	generated, err := GenerateNodePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ParsePrivateKey(generated)
	if err != nil || raw[0]&7 != 0 || raw[31]&128 != 0 || raw[31]&64 == 0 {
		t.Fatalf("generated key is not a clamped X25519 key: %v", err)
	}
	if string(EncodePrivateKey(raw)) != string(generated) {
		t.Fatal("encoding does not round trip")
	}
	for name, text := range map[string]string{
		"wrong prefix": "mkey:" + strings.Repeat("11", 32),
		"short":        "privkey:" + strings.Repeat("11", 31),
		"uppercase":    "privkey:" + strings.Repeat("AB", 32),
		"zero":         "privkey:" + strings.Repeat("00", 32),
		"not hex":      "privkey:" + strings.Repeat("zz", 32),
	} {
		if _, err := ParsePrivateKey([]byte(text)); !errors.Is(err, ErrInvalidMaterial) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFingerprints(t *testing.T) {
	t.Parallel()
	pin := ControlKeyFingerprint([32]byte{1})
	if canonical, err := VerifyFingerprint(strings.ToUpper(pin[:7])+pin[7:], pin); err != nil || canonical != pin {
		t.Fatalf("VerifyFingerprint = %q, %v", canonical, err)
	}
	if _, err := VerifyFingerprint(pin, ControlKeyFingerprint([32]byte{2})); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("different keys: %v", err)
	}
	if _, err := VerifyFingerprint("sha256:nope", pin); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("malformed pin: %v", err)
	}
}

func TestVerifyControlPin(t *testing.T) {
	t.Parallel()
	raw := [32]byte{7}
	text := EncodeControlPublicKey(raw)
	pin := ControlKeyFingerprint(raw)
	ck := sharedmtcp.ControlFingerprint(key.ControlPublic(raw))
	for name, value := range map[string]string{"sha256": pin, "ck": ck, "ck uppercase": strings.ToUpper(ck)} {
		if canonical, err := VerifyControlPin(value, text); err != nil || canonical != pin {
			t.Errorf("%s: %q, %v", name, canonical, err)
		}
	}
	other := sharedmtcp.ControlFingerprint(key.ControlPublic([32]byte{8}))
	if _, err := VerifyControlPin(other, text); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("another key's ck: %v", err)
	}
	if _, err := VerifyControlPin("abc", text); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("malformed pin: %v", err)
	}
}
