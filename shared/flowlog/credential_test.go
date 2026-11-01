package flowlog

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const (
	testWorkspace  = "01890f00-0000-7000-8000-000000000001"
	testCredential = "01890f00-0000-7000-8000-000000000002" //nolint:gosec // a public UUID, no secret
)

func testBinding() CredentialBinding {
	return CredentialBinding{ //nolint:gosec // test IDs, no secret
		WorkspaceID: "01890f00-0000-7000-8000-000000000001", CredentialID: "01890f00-0000-7000-8000-000000000002",
		Version: 1, Provider: ProviderS3,
	}
}

// A sealed credential opens only with the receiver's key and its binding.
func TestCredentialSealing(t *testing.T) {
	t.Parallel()
	receiver, _ := ecdh.X25519().GenerateKey(rand.Reader)
	credential := Credential{AccessKeyID: "TESTKEYID00000EXAMPLE", SecretAccessKey: "test-secret/value+1"}
	sealed, err := SealCredential(receiver.PublicKey(), credential, testBinding())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), credential.SecretAccessKey) || strings.Contains(string(sealed), credential.AccessKeyID) {
		t.Fatal("the sealed form shows the credential")
	}
	opened, err := OpenCredential(receiver, sealed, testBinding())
	if err != nil || opened != credential {
		t.Fatalf("opened %v %v", opened, err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenCredential(other, sealed, testBinding()); !errors.Is(err, ErrSealedCredential) {
		t.Errorf("another key opened it: %v", err)
	}
	for name, change := range map[string]func(*CredentialBinding){
		"workspace":  func(b *CredentialBinding) { b.WorkspaceID = "01890f00-0000-7000-8000-000000000009" },
		"credential": func(b *CredentialBinding) { b.CredentialID = "01890f00-0000-7000-8000-000000000009" },
		"version":    func(b *CredentialBinding) { b.Version = 2 },
		"provider": func(b *CredentialBinding) {
			b.Provider, b.AccountID = ProviderR2, strings.Repeat("a", 32)
		},
	} {
		binding := testBinding()
		change(&binding)
		if _, err := OpenCredential(receiver, sealed, binding); err == nil {
			t.Errorf("opened under another %s", name)
		}
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := OpenCredential(receiver, tampered, testBinding()); !errors.Is(err, ErrSealedCredential) {
		t.Errorf("a tampered credential opened: %v", err)
	}
	if credential.Suffix() != "MPLE" {
		t.Errorf("suffix %q", credential.Suffix())
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("put", "credential", credential,
		"wrapped", struct{ Secret Credential }{credential})
	printed := fmt.Sprintf("%v %+v %#v %s", credential, credential, credential, credential) + logged.String()
	if strings.Contains(printed, credential.SecretAccessKey) || strings.Contains(printed, "TESTKEYID") {
		t.Errorf("printed %q", printed)
	}
	if encoded, err := json.Marshal(struct{ Secret Credential }{credential}); err == nil {
		t.Errorf("encoded %s", encoded)
	}
}

func TestCredentialBounds(t *testing.T) {
	t.Parallel()
	receiver, _ := ecdh.X25519().GenerateKey(rand.Reader)
	good := Credential{AccessKeyID: "TESTKEYID00000EXAMPLE", SecretAccessKey: "test"}
	for name, test := range map[string]struct {
		credential Credential
		binding    CredentialBinding
	}{
		"short key id":     {Credential{AccessKeyID: "AKIA", SecretAccessKey: "s"}, testBinding()},
		"empty secret":     {Credential{AccessKeyID: good.AccessKeyID}, testBinding()},
		"secret space":     {Credential{AccessKeyID: good.AccessKeyID, SecretAccessKey: "a b"}, testBinding()},
		"r2 short key":     {good, CredentialBinding{WorkspaceID: testWorkspace, CredentialID: testCredential, Version: 1, Provider: ProviderR2, AccountID: strings.Repeat("a", 32)}},
		"r2 no account":    {Credential{AccessKeyID: strings.Repeat("a", 32), SecretAccessKey: "s"}, CredentialBinding{WorkspaceID: testWorkspace, CredentialID: testCredential, Version: 1, Provider: ProviderR2}},
		"s3 with account":  {good, CredentialBinding{WorkspaceID: testWorkspace, CredentialID: testCredential, Version: 1, Provider: ProviderS3, AccountID: strings.Repeat("a", 32)}},
		"unknown provider": {good, CredentialBinding{WorkspaceID: testWorkspace, CredentialID: testCredential, Version: 1, Provider: "gcs"}},
		"version 0":        {good, CredentialBinding{WorkspaceID: testWorkspace, CredentialID: testCredential, Provider: ProviderS3}},
		"upper-case id": {good, CredentialBinding{
			WorkspaceID: strings.ToUpper(testWorkspace), CredentialID: testCredential, Version: 1, Provider: ProviderS3,
		}},
		"empty id": {good, CredentialBinding{CredentialID: testCredential, Version: 1, Provider: ProviderS3}},
	} {
		if _, err := SealCredential(receiver.PublicKey(), test.credential, test.binding); err == nil {
			t.Errorf("%s: sealed", name)
		}
	}
	r2 := CredentialBinding{WorkspaceID: testWorkspace, CredentialID: testCredential, Version: 3, Provider: ProviderR2, AccountID: strings.Repeat("0", 32)}
	if _, err := SealCredential(receiver.PublicKey(), Credential{AccessKeyID: strings.Repeat("f", 32), SecretAccessKey: "s"}, r2); err != nil {
		t.Errorf("a valid R2 credential: %v", err)
	}
}
