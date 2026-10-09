package accountsession_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

func TestKeyringDigestsStableRotationCandidates(t *testing.T) {
	t.Parallel()

	token := mustToken(t)
	active := mustDigestKey(t, "active-v2", 0x11)
	previous := mustDigestKey(t, "previous-v1", 0x22)
	keyring, err := accountsession.NewKeyring(active, previous)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	digests, err := keyring.Digests(token)
	if err != nil {
		t.Fatalf("Digests() error = %v", err)
	}
	if len(digests) != 2 ||
		digests[0].KeyID().String() != "active-v2" ||
		digests[1].KeyID().String() != "previous-v1" {
		t.Fatalf("digest candidates = %+v, want active then previous", digests)
	}
	activeBytes := digests[0].Bytes()
	issued, err := keyring.ActiveDigest(token)
	if err != nil || issued != digests[0] {
		t.Fatal("issuance digest changed active verifier protocol")
	}
	if got := hex.EncodeToString(activeBytes[:]); got != "20feb2552dc2c4ddb617da7bdc4e808f2c9d398df1af75654af8128da35750a5" {
		t.Fatalf("active digest = %s, want stable protocol vector", got)
	}
	if fmt.Sprint(active) != "[REDACTED]" ||
		fmt.Sprintf("%#v", active) != "accountsession.DigestKey([REDACTED])" ||
		fmt.Sprint(digests[0]) != "[REDACTED]" ||
		fmt.Sprintf("%#v", keyring) != "accountsession.Keyring([REDACTED])" {
		t.Fatal("digest formatting disclosed secret evidence")
	}
}

func TestKeyringRejectsUnsafeRotation(t *testing.T) {
	t.Parallel()

	active := mustDigestKey(t, "active-v1", 0x11)
	if _, err := accountsession.NewKeyring(active, active); err == nil {
		t.Fatal("NewKeyring() accepted duplicate key IDs")
	}
	if _, err := accountsession.NewKeyring(active, mustDigestKey(t, "alias-v1", 0x11)); err == nil {
		t.Fatal("NewKeyring() accepted reused material under another ID")
	}
	id, err := accountsession.NewDigestKeyID("active-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	if _, err := accountsession.NewDigestKey(id, make([]byte, 32)); err == nil {
		t.Fatal("NewDigestKey() accepted all-zero material")
	}
	if _, err := accountsession.NewDigestKeyID(" invalid"); err == nil {
		t.Fatal("NewDigestKeyID() accepted whitespace")
	}
}

func mustToken(t *testing.T) accountsession.Token {
	t.Helper()
	token, err := accountsession.ParseToken(canonicalEnvelope)
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}
	return token
}

func mustDigestKey(t *testing.T, value string, fill byte) accountsession.DigestKey {
	t.Helper()
	id, err := accountsession.NewDigestKeyID(value)
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	key, err := accountsession.NewDigestKey(id, bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatalf("NewDigestKey() error = %v", err)
	}
	return key
}
