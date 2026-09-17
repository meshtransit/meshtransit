package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateLoginMaterialProtectedCandidateAndClearing(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	profile := &PrivateLoginConfig{cert: SecretFile{path: filepath.Join(directory, "cert")},
		privateKey: SecretFile{path: filepath.Join(directory, "private")}, clientSecret: SecretFile{path: filepath.Join(directory, "secret")}}
	for _, file := range []SecretFile{profile.cert, profile.privateKey, profile.clientSecret} {
		if err := os.WriteFile(file.path, []byte("synthetic-resident-candidate"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	material, err := profile.LoadMaterial(t.Context())
	if err != nil {
		t.Fatal("protected candidate rejected")
	}
	aliases := [][]byte{material.CertificatePEM, material.PrivateKeyPEM, material.ClientSecret}
	material.Clear()
	for _, alias := range aliases {
		if !bytes.Equal(alias, make([]byte, len(alias))) {
			t.Fatal("temporary candidate not cleared")
		}
	}
	if material.CertificatePEM != nil || material.PrivateKeyPEM != nil || material.ClientSecret != nil {
		t.Fatal("candidate references retained")
	}
	material.Clear()
	for _, test := range []struct {
		mode  os.FileMode
		valid bool
	}{{mode: 0o600, valid: true}, {mode: 0o644}} {
		if err := os.Chmod(profile.clientSecret.path, test.mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(profile.clientSecret.path)
		if err != nil || info.Mode().Perm() != test.mode {
			t.Fatal("fixture permissions not established")
		}
		material, err := profile.LoadMaterial(t.Context())
		if test.valid {
			if material == nil || err != nil {
				t.Fatal("protected complete candidate rejected")
			}
			material.Clear()
		} else if material != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("partial candidate released")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if material, err := profile.LoadMaterial(ctx); material != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("canceled candidate released")
	}
}

func TestPrivateLoginFileRejectsUnsafeCustodyWithoutRawErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		contents string
		mode     os.FileMode
	}{
		{name: "empty", contents: "", mode: 0o600},
		{name: "oversized", contents: strings.Repeat("x", 33), mode: 0o600},
		{name: "group readable", contents: "fixture", mode: 0o640},
		{name: "world readable", contents: "fixture", mode: 0o644},
		{name: "executable", contents: "fixture", mode: 0o700},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "candidate")
			if err := os.WriteFile(path, []byte(test.contents), test.mode); err != nil {
				t.Fatal(err)
			}
			contents, err := readPrivateLoginFile(t.Context(), SecretFile{path: path}, 32)
			if contents != nil || !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() {
				t.Fatal("unsafe custody released")
			}
		})
	}
	inside, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "credential")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(inside, "credential")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{inside, link, filepath.Join(inside, "missing")} {
		if contents, err := readPrivateLoginFile(t.Context(), SecretFile{path: path}, 32); contents != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("unconfined or non-regular custody released")
		}
	}
}

func TestPrivateLoginMaterialWithholdsCandidateAfterEarlierRotation(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	profile := &PrivateLoginConfig{
		cert:         SecretFile{path: filepath.Join(directory, "cert")},
		privateKey:   SecretFile{path: filepath.Join(directory, "private")},
		clientSecret: SecretFile{path: filepath.Join(directory, "secret")},
	}
	for _, file := range []SecretFile{profile.cert, profile.privateKey, profile.clientSecret} {
		if err := os.WriteFile(file.path, []byte("synthetic-material"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	aliases := [][]byte{}
	rotated := false
	material, err := profile.loadMaterialCandidate(t.Context(),
		func(ctx context.Context, file SecretFile, limit int64) ([]byte, privateLoginFileSnapshot, error) {
			contents, snapshot, readErr := readPrivateLoginFileSnapshot(ctx, file, limit)
			aliases = append(aliases, contents)
			if readErr == nil && file == profile.clientSecret {
				replacement := filepath.Join(directory, "replacement")
				if err := os.WriteFile(replacement, []byte("synthetic-material"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, profile.cert.path); err != nil {
					t.Fatal(err)
				}
				rotated = true
			}
			return contents, snapshot, readErr
		})
	if !rotated || material != nil || !errors.Is(err, ErrInvalid) {
		if material != nil {
			material.Clear()
		}
		t.Fatal("earlier material rotation released a mixed candidate")
	}
	for _, alias := range aliases {
		if !bytes.Equal(alias, make([]byte, len(alias))) {
			t.Fatal("failed material candidate not cleared")
		}
	}
}

func TestPrivateLoginFileDetectsOrdinaryReplacement(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "candidate")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := path + "-replacement"
	if err := os.WriteFile(replacement, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if unchangedPrivateLoginFile(before, after, 32) {
		t.Fatal("replacement accepted as same resident candidate")
	}
}
