package oidcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestSubjectDigestsFixExactStableNamespace(t *testing.T) {
	t.Parallel()
	params := pendingParamsFixture(t)
	identity := subjectIdentityFixture(t, params.Route.Issuer(), " Case-é ")
	id, err := NewDigestKeyID("subject-v1")
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	material[0] = 7
	key, err := NewSubjectKey(id, material)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewSubjectKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	digests, err := ring.Digests(params.Route, identity)
	if err != nil || len(digests) != 1 {
		t.Fatal("subject preparation failed")
	}
	input := []byte("meshtransit/oidc-auth/identity-subject/v1\x00")
	dep, provider := params.Route.DeploymentID().Bytes(), params.Route.ProviderID().Bytes()
	input = append(input, dep[:]...)
	input = append(input, provider[:]...)
	for _, value := range []string{id.String(), identity.Issuer(), identity.Subject()} {
		length := len(value)
		if length <= 0 || length > 65535 {
			t.Fatal("fixture exceeds encoding bound")
			return
		}
		input = binary.BigEndian.AppendUint16(input, uint16(length))
		input = append(input, value...)
	}
	mac := hmac.New(sha256.New, material)
	_, _ = mac.Write(input)
	got := digests[0].Bytes()
	if !hmac.Equal(got[:], mac.Sum(nil)) {
		t.Fatal("subject encoding drift")
	}
	material[0] = 9
	copyDigest := digests[0].Bytes()
	copyDigest[0] ^= 1
	again, err := ring.Digests(params.Route, identity)
	if err != nil || again[0] != digests[0] {
		t.Fatal("key or digest aliased mutable input")
	}
	for _, candidate := range []string{" case-é ", "Case-é", " Case-é ", " Case-é  "} {
		other, err := ring.Digests(params.Route, subjectIdentityFixture(t, params.Route.Issuer(), candidate))
		if err != nil || other[0] == digests[0] {
			t.Fatal("opaque subject normalized")
		}
	}
	otherIssuer := subjectIdentityFixture(t, params.Route.Issuer()+"/alias", identity.Subject())
	if _, err := ring.Digests(params.Route, otherIssuer); err == nil {
		t.Fatal("issuer alias admitted")
	}
	if fmt.Sprint(key) != "[REDACTED]" || fmt.Sprint(ring) != "[REDACTED]" || fmt.Sprint(digests[0]) != "[REDACTED]" {
		t.Fatal("key or digest disclosed")
	}
}

func TestSubjectNamespaceSeparatesIdentityFromAuthorityFences(t *testing.T) {
	t.Parallel()
	ring, err := NewSubjectKeyring(subjectKeyFixture(t, "stable-v1", 7))
	if err != nil {
		t.Fatal(err)
	}
	route := pendingParamsFixture(t).Route
	identity := subjectIdentityFixture(t, route.Issuer(), "opaque-stable")
	baseline, err := ring.Digests(route, identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"workspace", "client", "generation", "epoch", "deployment", "provider"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			other := route
			var parseErr error
			switch name {
			case "workspace":
				other.workspaceID, parseErr = workspace.ParseID("01890f00-0000-7000-8000-000000000777")
			case "client":
				other.clientID, parseErr = ParseClientID("01890f00-0000-7000-8000-000000000777")
			case "generation":
				other.providerGeneration++
			case "epoch":
				other.recoveryEpoch++
			case "deployment":
				other.deploymentID, parseErr = deployment.ParseID("01890f00-0000-7000-8000-000000000777")
			case "provider":
				other.providerID, parseErr = ParseProviderID("01890f00-0000-7000-8000-000000000777")
			}
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			digests, digestErr := ring.Digests(other, identity)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			mustDiffer := name == "deployment" || name == "provider"
			if (digests[0] != baseline[0]) != mustDiffer {
				t.Fatal("stable namespace or authority boundary drifted")
			}
		})
	}
}

func FuzzSubjectDigestsPreserveBoundedOpaqueIdentity(f *testing.F) {
	for _, subject := range []string{"subject", " Case-é ", " Case-é ", "\x00", "\xff", ""} {
		f.Add(subject)
	}
	f.Fuzz(func(t *testing.T, subject string) {
		params := pendingParamsFixture(t)
		evidence, err := NewTokenEvidence(TokenEvidenceParams{Issuer: params.Route.Issuer(), Subject: subject, Nonce: params.Secrets.Nonce(), IssuedAt: params.CreatedAt, ExpiresAt: params.ExpiresAt})
		if err != nil {
			return
		}
		if evidence.identity.Subject() != subject {
			t.Fatal("opaque subject normalized")
		}
		ring, err := NewSubjectKeyring(subjectKeyFixture(t, "fuzz-subject-v1", 7))
		if err != nil {
			t.Fatal(err)
		}
		first, err := ring.Digests(params.Route, evidence.identity)
		if err != nil || len(first) != 1 || !first[0].IsValid() {
			t.Fatal("valid identity digest rejected")
		}
		second, err := ring.Digests(params.Route, evidence.identity)
		if err != nil || first[0] != second[0] {
			t.Fatal("non-deterministic digest")
		}
	})
}

func TestSubjectKeyringBoundsRotation(t *testing.T) {
	t.Parallel()
	active := subjectKeyFixture(t, "active-v1", 1)
	previous := subjectKeyFixture(t, "previous-v1", 2)
	for _, candidate := range []struct {
		name     string
		active   SubjectKey
		previous []SubjectKey
	}{
		{name: "zero active"},
		{name: "zero previous", active: active, previous: []SubjectKey{{}}},
		{name: "same id", active: active, previous: []SubjectKey{active}},
		{name: "same material", active: active, previous: []SubjectKey{subjectKeyFixture(t, "other-id", 1)}},
		{name: "too many", active: active, previous: []SubjectKey{previous, previous}},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewSubjectKeyring(candidate.active, candidate.previous...); err == nil {
				t.Fatal("unsafe rotation accepted")
			}
		})
	}
	ring, err := NewSubjectKeyring(active, previous)
	if err != nil {
		t.Fatal(err)
	}
	params := pendingParamsFixture(t)
	digests, err := ring.Digests(params.Route, subjectIdentityFixture(t, params.Route.Issuer(), "opaque"))
	if err != nil || len(digests) != 2 || digests[0].KeyID() != active.ID() || digests[1].KeyID() != previous.ID() {
		t.Fatal("rotation order drift")
	}
	digests[0] = SubjectDigest{}
	again, err := ring.Digests(params.Route, subjectIdentityFixture(t, params.Route.Issuer(), "opaque"))
	if err != nil || !again[0].IsValid() {
		t.Fatal("candidate slice aliases ring")
	}
	var nilRing *SubjectKeyring
	if _, err := nilRing.Digests(params.Route, ExternalIdentity{}); err == nil {
		t.Fatal("nil ring accepted")
	}
}

func subjectKeyFixture(t *testing.T, value string, first byte) SubjectKey {
	t.Helper()
	id, err := NewDigestKeyID(value)
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	material[0] = first
	key, err := NewSubjectKey(id, material)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func subjectIdentityFixture(t *testing.T, issuer, subject string) ExternalIdentity {
	t.Helper()
	params := pendingParamsFixture(t)
	evidence, err := NewTokenEvidence(TokenEvidenceParams{Issuer: issuer, Subject: subject, Nonce: params.Secrets.Nonce(), IssuedAt: params.CreatedAt, ExpiresAt: params.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	return evidence.identity
}
