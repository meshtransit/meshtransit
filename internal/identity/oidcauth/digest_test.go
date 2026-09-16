package oidcauth

import (
	"bytes"
	"fmt"
	"testing"
)

func TestDigestKeySeparatesStateAndNoncePurposes(t *testing.T) {
	t.Parallel()

	keyID, err := NewDigestKeyID("oidc-digest-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	key, err := NewDigestKey(keyID, bytes.Repeat([]byte{0x6a}, 32))
	if err != nil {
		t.Fatalf("NewDigestKey() error = %v", err)
	}
	secrets := secretFixture(t)
	route := routeFixture(t)
	stateDigest, err := key.State(route.DeploymentID(), route.RecoveryEpoch(), secrets.State())
	if err != nil {
		t.Fatalf("DigestKey.State() error = %v", err)
	}
	nonce := Nonce{value: secrets.State().value}
	nonceDigest, err := key.Nonce(route.DeploymentID(), route.RecoveryEpoch(), nonce)
	if err != nil {
		t.Fatalf("DigestKey.Nonce() error = %v", err)
	}
	if stateDigest.Bytes() == nonceDigest.Bytes() {
		t.Fatal("state and nonce domains produced the same digest")
	}
	otherEpochDigest, err := key.State(route.DeploymentID(), route.RecoveryEpoch()+1, secrets.State())
	if err != nil || otherEpochDigest.Bytes() == stateDigest.Bytes() {
		t.Fatalf("DigestKey.State(other epoch) = (%v, %v), want distinct evidence", otherEpochDigest, err)
	}
	otherDeployment := mustDeploymentID(t, "01890f00-0000-7000-8000-000000000002")
	otherDeploymentDigest, err := key.State(otherDeployment, route.RecoveryEpoch(), secrets.State())
	if err != nil || otherDeploymentDigest.Bytes() == stateDigest.Bytes() {
		t.Fatalf("DigestKey.State(other Deployment) = (%v, %v), want distinct evidence", otherDeploymentDigest, err)
	}
	if stateDigest.Algorithm() != DigestAlgorithmHMACSHA256V1 ||
		stateDigest.KeyID() != keyID || !stateDigest.IsValid() {
		t.Fatal("state digest lost durable algorithm or key identity")
	}
	if fmt.Sprint(key) != "[REDACTED]" || fmt.Sprint(stateDigest) != "[REDACTED]" {
		t.Fatal("digest material formatted without redaction")
	}
}

func TestDigestKeyRejectsInvalidMaterial(t *testing.T) {
	t.Parallel()

	keyID, err := NewDigestKeyID("oidc-digest-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	for _, material := range [][]byte{nil, make([]byte, 31), make([]byte, 32)} {
		if _, err := NewDigestKey(keyID, material); err == nil {
			t.Fatalf("NewDigestKey(%d bytes) succeeded", len(material))
		}
	}
}
