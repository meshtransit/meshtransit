package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

func TestComposePrivateIdentityKeysOwnsCompleteResidentCandidate(t *testing.T) {
	t.Parallel()
	for _, withPrevious := range []bool{false, true} {
		t.Run(fmt.Sprintf("previous keys %t", withPrevious), func(t *testing.T) {
			t.Parallel()
			files, options, paths := privateIdentityCompositionFixture(t, withPrevious)
			keys, err := composePrivateIdentityKeys(t.Context(), files)
			if err != nil || keys == nil {
				t.Fatalf("compose private identity keys: %v", err)
			}
			if keys.transaction.ID().String() != "transaction-v1" || keys.verifier == nil ||
				keys.subjects == nil || keys.sessions == nil || keys.idempotency == nil || keys.rateLimit == nil {
				t.Fatal("resident candidate omitted an application key owner")
			}
			browserKeys := []struct {
				id       string
				material []byte
				fill     byte
			}{
				{id: keys.initiation.ID, material: keys.initiation.Material, fill: 1},
				{id: keys.capture.ID, material: keys.capture.Material, fill: 2},
				{id: keys.continuation.ID, material: keys.continuation.Material, fill: 3},
				{id: keys.csrf.ID, material: keys.csrf.Material, fill: 4},
			}
			for _, key := range browserKeys {
				if key.id == "" || !bytes.Equal(key.material, bytes.Repeat([]byte{key.fill}, 32)) {
					t.Fatal("candidate clear erased resident browser ownership")
				}
			}
			token, err := accountsession.ParseToken(managementCompositionToken)
			if err != nil {
				t.Fatal(err)
			}
			digests, err := keys.sessions.Digests(token)
			if err != nil {
				t.Fatal(err)
			}
			expectedCount := 1
			if withPrevious {
				expectedCount = 2
			}
			if len(digests) != expectedCount || digests[0].KeyID().String() != "session-v1" {
				t.Fatal("account Session rotation contract changed")
			}
			if withPrevious && digests[1].KeyID().String() != "session-v0" {
				t.Fatal("previous Session key missing")
			}
			independentFiles, err := config.NewPrivateIdentityKeyFiles(options)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := independentFiles.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			activeID, err := accountsession.NewDigestKeyID(candidate.SessionActive.ID)
			if err != nil {
				t.Fatal(err)
			}
			active, err := accountsession.NewDigestKey(activeID, candidate.SessionActive.Bytes[:])
			if err != nil {
				t.Fatal(err)
			}
			expectedRing, err := accountsession.NewKeyring(active)
			if err != nil {
				t.Fatal(err)
			}
			expectedDigest, err := expectedRing.ActiveDigest(token)
			if err != nil {
				t.Fatal(err)
			}
			candidate.Clear()
			if digests[0].Bytes() != expectedDigest.Bytes() {
				t.Fatal("resident Session digest differs from configured key")
			}
			if err := os.WriteFile(paths[0], []byte("invalid"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(keys.initiation.Material, bytes.Repeat([]byte{1}, 32)) {
				t.Fatal("resident key retained mutable filesystem input")
			}
			keys.initiation.Material[0] = 99
			if keys.capture.Material[0] != 2 || keys.csrf.Material[0] != 4 {
				t.Fatal("browser purposes alias resident buffers")
			}
		})
	}
}

func TestComposePrivateIdentityKeysRejectsFailureWithoutDisclosure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                                           string
		invalidFile, reusedKey, canceled, missingFiles bool
	}{
		{name: "invalid last file", invalidFile: true}, {name: "reused last key", reusedKey: true},
		{name: "canceled", canceled: true}, {name: "nil files", missingFiles: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			files, _, paths := privateIdentityCompositionFixture(t, true)
			if test.invalidFile {
				if err := os.WriteFile(paths[12], []byte("do-not-disclose-secret"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.reusedKey {
				encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
				if err := os.WriteFile(paths[12], []byte(encoded), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.canceled {
				cancel()
			}
			if test.missingFiles {
				files = nil
			}
			keys, err := composePrivateIdentityKeys(ctx, files)
			if keys != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) {
				t.Fatal("failed composition released partial resident owners")
			}
			if strings.Contains(err.Error(), paths[12]) || strings.Contains(err.Error(), "do-not-disclose-secret") {
				t.Fatal("composition disclosed input")
			}
		})
	}
	var missingContext context.Context
	keys, err := composePrivateIdentityKeys(missingContext, nil)
	if keys != nil || !errors.Is(err, errInvalidPrivateIdentityComposition) {
		t.Fatal("nil context accepted")
	}
}

func TestPrivateIdentityResidentDiagnosticsAreRedacted(t *testing.T) {
	t.Parallel()
	files, _, paths := privateIdentityCompositionFixture(t, false)
	keys, err := composePrivateIdentityKeys(t.Context(), files)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{keys, *keys} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "[REDACTED]" {
				t.Fatal("resident formatting disclosed key custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("resident serialization accepted")
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("private identity", "keys", value)
		if strings.Contains(logs.String(), "initiation-v1") || strings.Contains(logs.String(), paths[0]) {
			t.Fatal("resident structured log disclosed key custody")
		}
	}
}

func privateIdentityCompositionFixture(t *testing.T, withPrevious bool) (*config.PrivateIdentityKeyFiles, config.PrivateIdentityKeyOptions, []string) {
	t.Helper()
	options := config.PrivateIdentityKeyOptions{}
	references := []*config.ResidentKeyFile{
		&options.Initiation, &options.Capture, &options.Continuation, &options.ManagementCSRF,
		&options.TransactionDigest, &options.VerifierEncryption, &options.SubjectActive,
		&options.ProviderSession, &options.SessionActive, &options.Idempotency, &options.RateLimit,
	}
	names := []string{"initiation-v1", "capture-v1", "continuation-v1", "csrf-v1", "transaction-v1",
		"verifier-v1", "subject-v1", "provider-session-v1", "session-v1", "idempotency-v1", "rate-limit-v1"}
	if withPrevious {
		options.SubjectPrevious, options.SessionPrevious = &config.ResidentKeyFile{}, &config.ResidentKeyFile{}
		references = append(references, options.SubjectPrevious, options.SessionPrevious)
		names = append(names, "subject-v0", "session-v0")
	}
	directory := t.TempDir()
	paths := make([]string, len(references))
	for index, reference := range references {
		paths[index] = filepath.Join(directory, names[index]+".key")
		encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
		if err := os.WriteFile(paths[index], []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := config.NewSecretFile(paths[index])
		if err != nil {
			t.Fatal(err)
		}
		*reference = config.ResidentKeyFile{ID: names[index], File: file}
	}
	files, err := config.NewPrivateIdentityKeyFiles(options)
	if err != nil {
		t.Fatal(err)
	}
	return files, options, paths
}
