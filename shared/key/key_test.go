package key

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func mustDisco(t *testing.T, fill byte) DiscoPrivate {
	t.Helper()
	k, err := DiscoPrivateFromBytes(bytes.Repeat([]byte{fill}, Size))
	if err != nil {
		t.Fatalf("DiscoPrivateFromBytes: %v", err)
	}
	return k
}

func TestParsePublicIsStrict(t *testing.T) {
	t.Parallel()
	valid := "mtnode:" + strings.Repeat("ab", Size)
	if _, err := ParseNodePublic(valid); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	tests := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"wrong prefix", "mtdisco:" + strings.Repeat("ab", Size)},
		{"uppercase hex", "mtnode:" + strings.Repeat("AB", Size)},
		{"short", "mtnode:" + strings.Repeat("ab", Size-1)},
		{"long", valid + "00"},
		{"not hex", "mtnode:" + strings.Repeat("zz", Size)},
		{"zero key", "mtnode:" + strings.Repeat("00", Size)},
		{"no prefix", strings.Repeat("ab", Size)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseNodePublic(tt.text); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ParseNodePublic(%q) error = %v, want ErrInvalid", tt.text, err)
			}
		})
	}
}

func TestPublicTextRoundTrip(t *testing.T) {
	t.Parallel()
	disco := mustDisco(t, 7).Public()
	encoded, err := json.Marshal(struct{ K DiscoPublic }{disco})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct{ K DiscoPublic }
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.K != disco {
		t.Fatalf("round trip = %v, %v", decoded.K, err)
	}
	var zero DiscoPublic
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero key marshalled")
	}
}

func TestSharedSecretIsSymmetricAndRejectsLowOrder(t *testing.T) {
	t.Parallel()
	a, b := mustDisco(t, 1), mustDisco(t, 2)
	ab, err := a.Shared(b.Public())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := b.Shared(a.Public())
	if err != nil || ab != ba {
		t.Fatalf("shared secrets differ: %x %x %v", ab, ba, err)
	}
	// A low-order point (order 8) makes X25519 return all zeros.
	var lowOrder DiscoPublic
	copy(lowOrder[:], mustHex(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"))
	if _, err := a.Shared(lowOrder); !errors.Is(err, ErrLowOrder) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("low-order key accepted: %v", err)
	}
	var zero DiscoPrivate
	if _, err := zero.Shared(b.Public()); !errors.Is(err, ErrInvalid) {
		t.Fatal("unset private key performed X25519")
	}
}

func TestPrivateKeysNeverFormatMaterial(t *testing.T) {
	t.Parallel()
	disco := mustDisco(t, 9)
	signing, err := SigningPrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logger.Info("keys", "disco", disco, "signing", signing)
	out := fmt.Sprintf("%v %+v %#v %s %x %q", disco, disco, disco, signing, signing, signing) + logs.String()
	if strings.Contains(out, "0909") || !strings.Contains(out, "REDACTED") {
		t.Fatalf("private material leaked: %s", out)
	}
}

func TestSigningKeyIDAndVerify(t *testing.T) {
	t.Parallel()
	signing, err := SigningPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := signing.Public()
	// Fixed vector: changing the derivation would break every deployed key ID.
	if got := public.ID().String(); got != keyIDVector {
		t.Fatalf("key ID = %s, want %s", got, keyIDVector)
	}
	message := []byte("meshtransit")
	signature := signing.Sign(message)
	if !public.Verify(message, signature) {
		t.Fatal("valid signature rejected")
	}
	signature[0] ^= 1
	if public.Verify(message, signature) || public.Verify(message, nil) {
		t.Fatal("tampered signature accepted")
	}
	if _, err := SigningPrivateFromSeed(make([]byte, 32)); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero seed accepted")
	}
}

// keyIDVector is the key ID of the Ed25519 key with seed 32×0x01.
const keyIDVector = "d1e468f86f70505c" // computed independently with Python hashlib + cryptography

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func FuzzParsePublic(f *testing.F) {
	f.Add("mtnode:" + strings.Repeat("ab", Size))
	f.Add("mtnode:")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		k, err := ParseNodePublic(text)
		if err != nil {
			return
		}
		if k.IsZero() || k.String() != text {
			t.Fatalf("accepted non-canonical key %q", text)
		}
	})
}
