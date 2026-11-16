package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// RFC 7677 §3 exchange: user "user", password "pencil", salt and iteration
// count as below. The verifier keys must reproduce its client proof and
// server signature.
func TestSCRAMKeysMatchRFC7677(t *testing.T) {
	t.Parallel()
	salt, err := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	if err != nil {
		t.Fatal(err)
	}
	const authMessage = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," +
		"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	storedKey, serverKey, err := scramKeys([]byte("pencil"), salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	signature := hmac.New(sha256.New, serverKey)
	signature.Write([]byte(authMessage))
	if got := base64.StdEncoding.EncodeToString(signature.Sum(nil)); got != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatalf("server signature = %s", got)
	}
	proof, err := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	if err != nil {
		t.Fatal(err)
	}
	clientSignature := hmac.New(sha256.New, storedKey)
	clientSignature.Write([]byte(authMessage))
	clientKey := make([]byte, len(proof))
	for index, value := range clientSignature.Sum(nil) {
		clientKey[index] = proof[index] ^ value
	}
	if hashed := sha256.Sum256(clientKey); !bytes.Equal(hashed[:], storedKey) {
		t.Fatal("stored key does not match the RFC 7677 client proof")
	}
}

func TestSCRAMVerifierRoundTrip(t *testing.T) {
	t.Parallel()
	password := []byte(strings.Repeat("Kq7x", 10))
	verifier, err := scramVerifier(password, bytes.NewReader(bytes.Repeat([]byte{7}, scramSaltLength)))
	if err != nil {
		t.Fatal(err)
	}
	if !scramVerifierPattern.MatchString(verifier) || !strings.HasPrefix(verifier, "SCRAM-SHA-256$4096:") {
		t.Fatalf("verifier form = %q", verifier)
	}
	if !scramVerifierMatches(verifier, password) {
		t.Fatal("a verifier must match its own password")
	}
	for _, other := range []string{strings.Repeat("Kq7y", 10), "", "md5abc"} {
		if scramVerifierMatches(verifier, []byte(other)) {
			t.Fatalf("verifier matched %q", other)
		}
	}
	for _, stored := range []string{"", "md5" + strings.Repeat("0", 32), "SCRAM-SHA-256$0:AA==$AA==:AA==",
		"SCRAM-SHA-256$4096:%%$AA==:AA=="} {
		if scramVerifierMatches(stored, password) {
			t.Fatalf("malformed stored verifier %q matched", stored)
		}
	}
	if _, err := scramVerifier(password, bytes.NewReader(nil)); err == nil {
		t.Fatal("a failing entropy source must fail the verifier")
	}
}

func TestValidLoginPassword(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		password string
		valid    bool
	}{
		"32 printable":   {password: strings.Repeat("a", 32), valid: true},
		"256 printable":  {password: strings.Repeat("Z", 256), valid: true},
		"31 characters":  {password: strings.Repeat("a", 31)},
		"257 characters": {password: strings.Repeat("a", 257)},
		"space":          {password: strings.Repeat("a", 31) + " "},
		"quote":          {password: strings.Repeat("a", 31) + "'"},
		"backslash":      {password: strings.Repeat("a", 31) + `\`},
		"non-ASCII":      {password: strings.Repeat("a", 31) + "é"},
		"newline":        {password: strings.Repeat("a", 31) + "\n"},
	} {
		if err := validLoginPassword([]byte(test.password)); (err == nil) != test.valid {
			t.Errorf("%s: error = %v, want valid %v", name, err, test.valid)
		}
	}
}
