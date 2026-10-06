package oidcauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParsePreAuthCookieAcceptsOnlyBoundedCanonicalEntropy(t *testing.T) {
	t.Parallel()
	cookie := secretFixture(t).PreAuthCookie()
	parsed, err := ParsePreAuthCookie(cookie.Encoded())
	if err != nil || parsed.Encoded() != cookie.Encoded() {
		t.Fatal("canonical cookie did not round trip")
	}
	for _, test := range []struct{ name, value string }{
		{name: "empty"},
		{name: "short", value: cookie.Encoded()[:42]},
		{name: "oversized", value: strings.Repeat("A", 8193)},
		{name: "padded", value: cookie.Encoded() + "="},
		{name: "quoted", value: `"` + cookie.Encoded() + `"`},
		{name: "newline", value: cookie.Encoded()[:42] + "\n"},
		{name: "zero", value: base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		{name: "noncanonical trailing bits", value: strings.Repeat("A", 42) + "B"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, parseErr := ParsePreAuthCookie(test.value)
			if !errors.Is(parseErr, ErrInvalidPreAuthCookie) || got.IsValid() || strings.Contains(parseErr.Error(), test.value) && test.value != "" {
				t.Fatal("unsafe cookie accepted or input echoed")
			}
		})
	}
}

func TestCookieDigestBindsEveryAuthorityDimensionAndPurpose(t *testing.T) {
	t.Parallel()
	params := pendingParamsFixture(t)
	key, cookie, binding := params.DigestKey, params.Secrets.PreAuthCookie(), bindingFixture(t)
	digest, err := key.PreAuthCookie(binding, cookie)
	if err != nil || !key.VerifyPreAuthCookie(binding, cookie, digest) {
		t.Fatal("exact cookie proof rejected")
	}
	for _, test := range []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "deployment", mutate: func(b *Binding) { b.DeploymentID = mustDeploymentID(t, "01890f00-0000-7000-8000-000000000099") }},
		{name: "provider", mutate: func(b *Binding) { b.ProviderID = mustProviderID(t, "01890f00-0000-7000-8000-000000000099") }},
		{name: "client", mutate: func(b *Binding) { b.ClientID = mustClientID(t, "01890f00-0000-7000-8000-000000000099") }},
		{name: "transaction", mutate: func(b *Binding) { b.TransactionID = mustTransactionID(t, "01890f00-0000-7000-8000-000000000099") }},
		{name: "provider generation", mutate: func(b *Binding) { b.ProviderGeneration++ }},
		{name: "recovery epoch", mutate: func(b *Binding) { b.RecoveryEpoch++ }},
		{name: "redirect", mutate: func(b *Binding) { b.RedirectID = "other.callback" }},
		{name: "return route", mutate: func(b *Binding) { b.ReturnRouteID = "other.home" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			other := binding
			test.mutate(&other)
			if key.VerifyPreAuthCookie(other, cookie, digest) {
				t.Fatal("substituted authority context accepted")
			}
		})
	}
	sameState, err := ParseState(cookie.Encoded())
	if err != nil {
		t.Fatal(err)
	}
	stateDigest, err := key.State(binding.DeploymentID, binding.RecoveryEpoch, sameState)
	if err != nil {
		t.Fatal(err)
	}
	if stateDigest.Bytes() == digest.Bytes() {
		t.Fatal("cookie reused state HMAC purpose")
	}
	if key.VerifyPreAuthCookie(binding, PreAuthCookie{}, digest) || key.VerifyPreAuthCookie(Binding{}, cookie, digest) {
		t.Fatal("missing cookie or context accepted")
	}
	otherCookie := cookie
	otherCookie.value[0] ^= 1
	if key.VerifyPreAuthCookie(binding, otherCookie, digest) {
		t.Fatal("wrong cookie accepted")
	}
	otherKey, err := NewDigestKey(key.ID(), bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if otherKey.VerifyPreAuthCookie(binding, cookie, digest) {
		t.Fatal("wrong key material accepted")
	}
	otherID, err := NewDigestKeyID("other-v1")
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err = NewDigestKey(otherID, key.material[:])
	if err != nil {
		t.Fatal(err)
	}
	if otherKey.VerifyPreAuthCookie(binding, cookie, digest) {
		t.Fatal("wrong key generation accepted")
	}
	if _, err := NewCookieDigest("sha256", key.ID(), digest.Bytes()); !errors.Is(err, ErrInvalidCookieDigest) {
		t.Fatal("unsupported digest algorithm accepted")
	}
}

func TestPreAuthEvidenceAlwaysFormatsRedacted(t *testing.T) {
	t.Parallel()
	params := pendingParamsFixture(t)
	digest, err := params.DigestKey.PreAuthCookie(bindingFixture(t), params.Secrets.PreAuthCookie())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{params.Secrets.PreAuthCookie(), digest} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if !strings.Contains(fmt.Sprintf(format, value), "[REDACTED]") {
				t.Fatal("format disclosed evidence")
			}
		}
	}
	if digest.LogValue().String() != "[REDACTED]" || params.Secrets.PreAuthCookie().LogValue().String() != "[REDACTED]" {
		t.Fatal("structured log disclosed evidence")
	}
}

func FuzzParsePreAuthCookie(f *testing.F) {
	f.Add(strings.Repeat("A", 42) + "E")
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		cookie, err := ParsePreAuthCookie(value)
		if err == nil && (!cookie.IsValid() || cookie.Encoded() != value || len(value) != 43) {
			t.Fatal("parser accepted noncanonical material")
		}
	})
}
