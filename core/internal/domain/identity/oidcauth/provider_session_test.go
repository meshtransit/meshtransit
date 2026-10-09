package oidcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestProviderSessionDigestPreservesExactOpaqueNamespace(t *testing.T) {
	t.Parallel()
	exchange := issueExchangeFixture(t)
	route := exchange.claimed.snapshot.Route()
	identity := exchange.Identity()
	identity.sessionID = " Synthetic-é-SID "
	id, err := NewDigestKeyID("sid-v1")
	if err != nil {
		t.Fatal(err)
	}
	material := []byte("abcdef0123456789abcdef0123456789")
	key, err := NewProviderSessionKey(id, material)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := key.session(route, identity)
	if err != nil || !digest.IsValid() {
		t.Fatal("valid SID rejected")
	}
	// Independent encoder pins purpose, order, UTF-8 byte lengths and exact SID.
	mac := hmac.New(sha256.New, material)
	_, _ = mac.Write([]byte("meshtransit/oidc-auth/provider-session/v1\x00"))
	dep, provider := route.DeploymentID().Bytes(), route.ProviderID().Bytes()
	_, _ = mac.Write(dep[:])
	_, _ = mac.Write(provider[:])
	for _, field := range []struct {
		value  string
		length uint16
	}{{"sid-v1", 6}, {route.Issuer(), 45}, {" Synthetic-é-SID ", 18}} {
		if len(field.value) != int(field.length) {
			t.Fatal("invalid fixture length")
		}
		if err := binary.Write(mac, binary.BigEndian, field.length); err != nil {
			t.Fatal(err)
		}
		_, _ = mac.Write([]byte(field.value))
	}
	actual := digest.Bytes()
	if !hmac.Equal(actual[:], mac.Sum(nil)) {
		t.Fatal("SID HMAC protocol drift")
	}
	if hex.EncodeToString(actual[:]) != "8e366bd31cbd453a003c58b3596f8daf48277e2fde7fcafef42983ee640cdcd3" {
		t.Fatal("SID HMAC stable protocol vector drift")
	}
	for _, name := range []string{"trimmed SID", "different provider", "different deployment", "different issuer"} {
		t.Run(name, func(t *testing.T) {
			candidateRoute, candidateIdentity := route, identity
			switch name {
			case "trimmed SID":
				candidateIdentity.sessionID = "Synthetic-é-SID"
			case "different provider":
				candidateRoute.providerID[15] ^= 1
			case "different deployment":
				candidateRoute.deploymentID[15] ^= 1
			case "different issuer":
				candidateRoute.issuer += "/other"
				candidateIdentity.issuer = candidateRoute.issuer
			}
			candidate, candidateErr := key.session(candidateRoute, candidateIdentity)
			if candidateErr != nil || candidate == digest {
				t.Fatal("opaque namespace collapsed")
			}
		})
	}
	route.providerGeneration++
	route.recoveryEpoch++
	route.clientID[15] ^= 1
	same, err := key.session(route, identity)
	if err != nil || same != digest {
		t.Fatal("mutable authority fields changed stable SID namespace")
	}
	identity.sessionID = ""
	absent, err := key.session(route, identity)
	if err != nil || absent.IsValid() || absent.Bytes() != ([32]byte{}) {
		t.Fatal("absent SID manufactured evidence")
	}
	if fmt.Sprint(key) != "[REDACTED]" || fmt.Sprint(digest) != "[REDACTED]" ||
		digest.LogValue().String() != "[REDACTED]" {
		t.Fatal("SID evidence leaked through formatting")
	}
	if _, err := (ProviderSessionKey{}).session(route, identity); err == nil {
		t.Fatal("zero key accepted")
	}
	identity.issuer += "/unconfigured"
	if _, err := key.session(route, identity); err == nil {
		t.Fatal("unconfigured issuer accepted")
	}
}
