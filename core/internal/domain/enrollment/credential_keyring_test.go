package enrollment_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
)

func TestCredentialKeyringDigestAndVerify(t *testing.T) {
	t.Parallel()

	deploymentID := mustDeploymentID(t, "01890f00-0000-7000-8000-000000000001")
	token := mustCredentialToken(t, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	active := mustDigestKey(t, "active-v2", 0x22)
	previous := mustDigestKey(t, "previous-v1", 0x11)
	keyring, err := enrollment.NewCredentialKeyring(active, previous)
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}

	digest, err := keyring.Digest(deploymentID, 7, token)
	if err != nil {
		t.Fatalf("CredentialKeyring.Digest() error = %v", err)
	}
	if digest.Algorithm() != enrollment.DigestAlgorithmHMACSHA256 || digest.KeyID() != active.ID() ||
		!digest.IsValid() || digest.Bytes() == ([32]byte{}) || digest.Fingerprint() == ([16]byte{}) {
		t.Fatalf("CredentialKeyring.Digest() returned incomplete durable state")
	}
	digestBytes := digest.Bytes()
	if got := hex.EncodeToString(digestBytes[:]); got != "19f0d86733b52f83a3fb2831351ac8d15bddaf65f95eda16f0380883ffc699e3" {
		t.Fatalf("CredentialKeyring.Digest() = %q, want stable protocol vector", got)
	}
	if !keyring.Verify(deploymentID, 7, token, digest) {
		t.Fatal("CredentialKeyring.Verify() rejected active-key digest")
	}

	previousOnly, err := enrollment.NewCredentialKeyring(previous)
	if err != nil {
		t.Fatalf("NewCredentialKeyring(previous) error = %v", err)
	}
	previousDigest, err := previousOnly.Digest(deploymentID, 7, token)
	if err != nil {
		t.Fatalf("previous CredentialKeyring.Digest() error = %v", err)
	}
	if !keyring.Verify(deploymentID, 7, token, previousDigest) {
		t.Fatal("CredentialKeyring.Verify() rejected previous-key digest")
	}
}

func TestCredentialKeyringVerificationFailsClosed(t *testing.T) {
	t.Parallel()

	deploymentID := mustDeploymentID(t, "01890f00-0000-7000-8000-000000000001")
	otherDeployment := mustDeploymentID(t, "01890f00-0000-7000-8000-000000000002")
	token := mustCredentialToken(t, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	otherToken := mustCredentialToken(t, "ICEeHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE")
	active := mustDigestKey(t, "active-v2", 0x22)
	unknown := mustDigestKey(t, "unknown-v3", 0x33)
	keyring, err := enrollment.NewCredentialKeyring(active)
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	digest, err := keyring.Digest(deploymentID, 7, token)
	if err != nil {
		t.Fatalf("CredentialKeyring.Digest() error = %v", err)
	}
	unknownKeyring, err := enrollment.NewCredentialKeyring(unknown)
	if err != nil {
		t.Fatalf("NewCredentialKeyring(unknown) error = %v", err)
	}
	unknownDigest, err := unknownKeyring.Digest(deploymentID, 7, token)
	if err != nil {
		t.Fatalf("unknown CredentialKeyring.Digest() error = %v", err)
	}

	tests := []struct {
		name         string
		deploymentID deployment.ID
		epoch        int64
		token        enrollment.CredentialToken
		digest       enrollment.CredentialDigest
	}{
		{name: "other deployment", deploymentID: otherDeployment, epoch: 7, token: token, digest: digest},
		{name: "other recovery epoch", deploymentID: deploymentID, epoch: 8, token: token, digest: digest},
		{name: "other token", deploymentID: deploymentID, epoch: 7, token: otherToken, digest: digest},
		{name: "unknown key", deploymentID: deploymentID, epoch: 7, token: token, digest: unknownDigest},
		{name: "invalid deployment", epoch: 7, token: token, digest: digest},
		{name: "invalid epoch", deploymentID: deploymentID, token: token, digest: digest},
		{name: "invalid token", deploymentID: deploymentID, epoch: 7, digest: digest},
		{name: "invalid digest", deploymentID: deploymentID, epoch: 7, token: token},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if keyring.Verify(test.deploymentID, test.epoch, test.token, test.digest) {
				t.Fatal("CredentialKeyring.Verify() accepted mismatched credential evidence")
			}
		})
	}
	var nilKeyring *enrollment.CredentialKeyring
	if nilKeyring.Verify(deploymentID, 7, token, digest) {
		t.Fatal("nil CredentialKeyring accepted credential evidence")
	}
}

func TestCredentialKeyringValidationAndDefensiveCopy(t *testing.T) {
	t.Parallel()

	id, err := enrollment.NewDigestKeyID("active-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	material := bytesOf(0x44, 32)
	key, err := enrollment.NewDigestKey(id, material)
	if err != nil {
		t.Fatalf("NewDigestKey() error = %v", err)
	}
	material[0] = 0
	keyring, err := enrollment.NewCredentialKeyring(key)
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	deploymentID := mustDeploymentID(t, "01890f00-0000-7000-8000-000000000001")
	token := mustCredentialToken(t, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	digest, err := keyring.Digest(deploymentID, 1, token)
	if err != nil || !keyring.Verify(deploymentID, 1, token, digest) {
		t.Fatalf("key material changed through caller slice: digest error = %v", err)
	}

	if fmt.Sprint(key) != "[REDACTED]" || fmt.Sprintf("%#v", key) != "enrollment.DigestKey([REDACTED])" ||
		fmt.Sprint(digest) != "[REDACTED]" ||
		fmt.Sprintf("%#v", digest) != "enrollment.CredentialDigest([REDACTED])" ||
		fmt.Sprint(keyring) != "[REDACTED]" ||
		fmt.Sprintf("%#v", keyring) != "enrollment.CredentialKeyring([REDACTED])" ||
		fmt.Sprint(*keyring) != "[REDACTED]" ||
		fmt.Sprintf("%#v", *keyring) != "enrollment.CredentialKeyring([REDACTED])" {
		t.Fatal("credential cryptography formatting disclosed secret state")
	}
}

func TestCredentialKeyringRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	validID, err := enrollment.NewDigestKeyID("active-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	for _, value := range []string{"", " active", "active key", "_active", "active/v1"} {
		if _, err := enrollment.NewDigestKeyID(value); !errors.Is(err, enrollment.ErrInvalidDigestKey) {
			t.Fatalf("NewDigestKeyID(%q) error = %v, want ErrInvalidDigestKey", value, err)
		}
	}
	if _, err := enrollment.NewDigestKey(validID, bytesOf(1, 31)); !errors.Is(err, enrollment.ErrInvalidDigestKey) {
		t.Fatalf("NewDigestKey(short) error = %v, want ErrInvalidDigestKey", err)
	}
	if _, err := enrollment.NewDigestKey(validID, make([]byte, 32)); !errors.Is(err, enrollment.ErrInvalidDigestKey) {
		t.Fatalf("NewDigestKey(zero) error = %v, want ErrInvalidDigestKey", err)
	}
	active := mustDigestKey(t, "active-v1", 0x11)
	duplicate := mustDigestKey(t, "active-v1", 0x22)
	third := mustDigestKey(t, "third-v3", 0x33)
	if _, err := enrollment.NewCredentialKeyring(active, duplicate); !errors.Is(err, enrollment.ErrInvalidCredentialKeyring) {
		t.Fatalf("NewCredentialKeyring(duplicate) error = %v, want ErrInvalidCredentialKeyring", err)
	}
	if _, err := enrollment.NewCredentialKeyring(active, duplicate, third); !errors.Is(err, enrollment.ErrInvalidCredentialKeyring) {
		t.Fatalf("NewCredentialKeyring(three keys) error = %v, want ErrInvalidCredentialKeyring", err)
	}
	if _, err := (&enrollment.CredentialKeyring{}).Digest(
		mustDeploymentID(t, "01890f00-0000-7000-8000-000000000001"),
		1,
		mustCredentialToken(t, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"),
	); !errors.Is(err, enrollment.ErrInvalidCredentialKeyring) {
		t.Fatalf("zero CredentialKeyring.Digest() error = %v, want ErrInvalidCredentialKeyring", err)
	}
}

func mustDeploymentID(t *testing.T, value string) deployment.ID {
	t.Helper()

	id, err := deployment.ParseID(value)
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	return id
}

func mustCredentialToken(t *testing.T, value string) enrollment.CredentialToken {
	t.Helper()

	token, err := enrollment.ParseCredentialToken(value)
	if err != nil {
		t.Fatalf("enrollment.ParseCredentialToken() error = %v", err)
	}
	return token
}

func mustDigestKey(t *testing.T, idValue string, fill byte) enrollment.DigestKey {
	t.Helper()

	id, err := enrollment.NewDigestKeyID(idValue)
	if err != nil {
		t.Fatalf("enrollment.NewDigestKeyID() error = %v", err)
	}
	key, err := enrollment.NewDigestKey(id, bytesOf(fill, 32))
	if err != nil {
		t.Fatalf("enrollment.NewDigestKey() error = %v", err)
	}
	return key
}

func bytesOf(value byte, length int) []byte {
	return []byte(strings.Repeat(string([]byte{value}), length))
}
