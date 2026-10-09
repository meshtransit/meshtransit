package config

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
	"testing"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

func privateLoginConstructionFixture(t *testing.T) *PrivateLoginConfig {
	t.Helper()
	process, document := privateLoginTestDocument(t)
	options := privateIdentityKeyOptionsFixture(t)
	directory := t.TempDir()
	write := func(name string, contents []byte) SecretFile {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal("write owned protected fixture")
		}
		file, err := NewSecretFile(path)
		if err != nil {
			t.Fatal("construct owned fixture reference")
		}
		return file
	}
	keys, ok := document["keys"].(map[string]any)
	if !ok {
		t.Fatal("fixture key document missing")
	}
	for _, field := range []struct {
		name string
		key  ResidentKeyFile
	}{
		{"initiation", options.Initiation}, {"capture", options.Capture},
		{"continuation", options.Continuation}, {"management_csrf", options.ManagementCSRF},
		{"transaction_digest", options.TransactionDigest}, {"verifier_encryption", options.VerifierEncryption},
		{"subject_active", options.SubjectActive}, {"provider_session", options.ProviderSession},
	} {
		keys[field.name] = map[string]string{"id": field.key.ID, "file": field.key.File.path}
	}
	subjectContents := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32))
	subjectPrevious := write("previous-subject", []byte(subjectContents))
	keys["subject_previous"] = map[string]string{"id": "subject-previous-v1", "file": subjectPrevious.path}
	sessionContents := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32))
	sessionPrevious := write("previous-session", []byte(sessionContents))
	id, err := accountsession.NewDigestKeyID("session-previous-v1")
	if err != nil {
		t.Fatal("construct previous fixture generation")
	}
	process.API.AccountSessionDigest.Active.MaterialFile = options.SessionActive.File
	process.API.AccountSessionDigest.Previous = &AccountSessionDigestKeyConfig{ID: id, MaterialFile: sessionPrevious}
	process.API.IdempotencyDigest.MaterialFile = options.Idempotency.File
	process.API.RateLimitDigest.MaterialFile = options.RateLimit.File
	for _, name := range []string{"tls_certificate_file", "tls_private_key_file", "client_secret_file"} {
		file := write(name, []byte("synthetic-owned-material"))
		document[name] = file.path
	}
	source := write("login.json", privateLoginTestJSON(t, document))
	profile, err := (&PrivateLoginFile{file: source}).Load(t.Context(), process)
	if err != nil {
		t.Fatal("load real protected JSON fixture")
	}
	return profile
}

func privateLoginConstructionReferences(profile *PrivateLoginConfig) []SecretFile {
	references := []SecretFile{profile.source.reference}
	for _, key := range profile.keys.keys {
		references = append(references, key.File)
	}
	return append(references, profile.cert, profile.privateKey, profile.clientSecret)
}

func replacePrivateLoginConstructionFile(t *testing.T, file SecretFile) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(file.path))
	if err != nil {
		t.Fatal("scope owned rotation fixture")
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error("close owned rotation fixture scope")
		}
	}()
	name := filepath.Base(file.path)
	contents, err := root.ReadFile(name)
	if err != nil {
		t.Fatal("read owned rotation fixture")
	}
	defer clear(contents)
	if err := root.WriteFile("replacement", contents, 0o600); err != nil {
		t.Fatal("write owned replacement fixture")
	}
	if err := root.Rename("replacement", name); err != nil {
		t.Fatal("rotate owned protected fixture")
	}
}

func TestPrivateLoginConstructionRechecksEveryOriginalReference(t *testing.T) {
	t.Parallel()
	for index := range 17 {
		t.Run(fmt.Sprintf("reference-%02d", index), func(t *testing.T) {
			profile := privateLoginConstructionFixture(t)
			candidate, err := profile.LoadConstruction(t.Context())
			if err != nil {
				t.Fatal("complete protected candidate rejected")
			}
			defer candidate.Clear()
			if candidate.CheckCurrent(t.Context()) != nil {
				t.Fatal("unchanged candidate rejected")
			}
			replacePrivateLoginConstructionFile(t, privateLoginConstructionReferences(profile)[index])
			if err := candidate.CheckCurrent(t.Context()); !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
				t.Fatal("rotated original reference released")
			}
		})
	}
}

func TestPrivateLoginConstructionWithholdsMixedBundle(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		index int
	}{{"profile", 0}, {"first-key", 1}, {"previous-subject", 12}, {"previous-session", 13}, {"certificate", 14}} {
		t.Run(test.name, func(t *testing.T) {
			profile := privateLoginConstructionFixture(t)
			var aliases [][]byte
			candidate, err := profile.loadConstructionCandidate(t.Context(),
				func(ctx context.Context, file SecretFile) ([32]byte, privateIdentityKeySnapshot, error) {
					return file.readPrivateIdentityKeySnapshot(ctx)
				},
				func(ctx context.Context, file SecretFile, limit int64) ([]byte, privateLoginFileSnapshot, error) {
					contents, snapshot, readErr := readPrivateLoginFileSnapshot(ctx, file, limit)
					aliases = append(aliases, contents)
					if file == profile.clientSecret {
						replacePrivateLoginConstructionFile(t, privateLoginConstructionReferences(profile)[test.index])
					}
					return contents, snapshot, readErr
				})
			if candidate != nil {
				candidate.Clear()
				t.Fatal("mixed startup bundle released")
			}
			if !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
				t.Fatal("mixed bundle did not return closed failure")
			}
			for _, alias := range aliases {
				if !bytes.Equal(alias, make([]byte, len(alias))) {
					t.Fatal("failed candidate retained material")
				}
			}
		})
	}
}

func TestPrivateLoginConstructionClearAndRedaction(t *testing.T) {
	t.Parallel()
	profile := privateLoginConstructionFixture(t)
	candidate, err := profile.LoadConstruction(t.Context())
	if err != nil {
		t.Fatal("complete candidate rejected")
	}
	if fmt.Sprint(candidate) != redactedValue || fmt.Sprintf("%#v", candidate) != redactedValue ||
		candidate.LogValue().Kind() != slog.KindString || candidate.LogValue().String() != redactedValue {
		t.Fatal("construction diagnostics disclosed")
	}
	if body, err := json.Marshal(candidate); body != nil || err == nil {
		t.Fatal("construction serialized")
	}
	keys, material := candidate.Keys, candidate.Material
	previousSubject, previousSession := keys.SubjectPrevious, keys.SessionPrevious
	aliases := [][]byte{material.CertificatePEM, material.PrivateKeyPEM, material.ClientSecret}
	candidate.Clear()
	candidate.Clear()
	if candidate.Keys != nil || candidate.Material != nil || candidate.source.info != nil ||
		keys.snapshots != ([13]privateIdentityKeySnapshot{}) || material.snapshots != ([3]privateLoginFileSnapshot{}) {
		t.Fatal("cleared candidate retained ownership metadata")
	}
	purposes := keys.purposes()
	for _, key := range append(purposes[:], previousSubject, previousSession) {
		if key != nil && (key.ID != "" || key.Bytes != ([32]byte{})) {
			t.Fatal("cleared candidate retained current or previous key")
		}
	}
	for _, alias := range aliases {
		if !bytes.Equal(alias, make([]byte, len(alias))) {
			t.Fatal("cleared candidate retained material")
		}
	}
	if !errors.Is(candidate.CheckCurrent(t.Context()), ErrInvalid) {
		t.Fatal("cleared candidate remained releasable")
	}
}

func TestPrivateLoginConstructionClearsLateReadFailureAndCancellation(t *testing.T) {
	t.Parallel()
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled-%t", canceled), func(t *testing.T) {
			profile := privateLoginConstructionFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var aliases [][]byte
			candidate, err := profile.loadConstructionCandidate(ctx,
				func(ctx context.Context, file SecretFile) ([32]byte, privateIdentityKeySnapshot, error) {
					return file.readPrivateIdentityKeySnapshot(ctx)
				},
				func(ctx context.Context, file SecretFile, limit int64) ([]byte, privateLoginFileSnapshot, error) {
					contents, snapshot, readErr := readPrivateLoginFileSnapshot(ctx, file, limit)
					aliases = append(aliases, contents)
					if file == profile.clientSecret {
						if canceled {
							cancel()
						} else {
							readErr = errors.New("synthetic-sensitive-filesystem-diagnostic")
						}
					}
					return contents, snapshot, readErr
				})
			if candidate != nil {
				candidate.Clear()
				t.Fatal("late failure released partial construction")
			}
			if !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
				t.Fatal("late failure released unclassified diagnostics")
			}
			for _, alias := range aliases {
				if !bytes.Equal(alias, make([]byte, len(alias))) {
					t.Fatal("late failure retained temporary material")
				}
			}
		})
	}
}

func TestPrivateLoginConstructionRejectsCanceledUnsafeAndUnownedProfile(t *testing.T) {
	t.Parallel()
	profile := privateLoginConstructionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if candidate, err := profile.LoadConstruction(ctx); candidate != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid context released candidate")
		}
	}
	process, document := privateLoginTestDocument(t)
	unowned, err := parsePrivateLoginConfig(privateLoginTestJSON(t, document), process)
	if err != nil {
		t.Fatal("parse source-only fixture")
	}
	if candidate, err := unowned.LoadConstruction(t.Context()); candidate != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("unloaded JSON profile released candidate")
	}
	for _, test := range []struct {
		index int
		mode  os.FileMode
	}{{index: 0, mode: 0o644}, {index: 1, mode: 0o644}, {index: 16, mode: 0o644}} {
		t.Run(fmt.Sprintf("unsafe-mode-%02d", test.index), func(t *testing.T) {
			profile := privateLoginConstructionFixture(t)
			if err := os.Chmod(privateLoginConstructionReferences(profile)[test.index].path, test.mode); err != nil {
				t.Fatal("establish unsafe fixture mode")
			}
			if candidate, err := profile.LoadConstruction(t.Context()); candidate != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe source/key/credential released candidate")
			}
		})
	}
}
