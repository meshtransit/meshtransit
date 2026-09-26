package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPrivateIdentityKeyStrictFileCustody(t *testing.T) {
	t.Parallel()
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x91}, 32))
	tests := []struct {
		name, contents string
		mode           os.FileMode
		valid          bool
	}{
		{name: "owner read", contents: encoded, mode: 0o400, valid: true},
		{name: "owner read write", contents: encoded, mode: 0o600, valid: true},
		{name: "group read", contents: encoded, mode: 0o440, valid: true},
		{name: "owner write group read", contents: encoded, mode: 0o640, valid: true},
		{name: "lf", contents: encoded + "\n", mode: 0o600, valid: true},
		{name: "crlf", contents: encoded + "\r\n", mode: 0o600, valid: true},
		{name: "world readable", contents: encoded, mode: 0o604},
		{name: "executable", contents: encoded, mode: 0o700},
		{name: "write only", contents: encoded, mode: 0o200},
		{name: "empty", mode: 0o600},
		{name: "padded", contents: encoded + "=", mode: 0o600},
		{name: "extra lf", contents: encoded + "\n\n", mode: 0o600},
		{name: "space", contents: encoded + " ", mode: 0o600},
		{name: "large file", contents: strings.Repeat("a", 4096), mode: 0o600},
		{name: "zero material", contents: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), mode: 0o600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "private.key")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			key, err := (SecretFile{path: path}).readPrivateIdentityKey(t.Context())
			if test.valid {
				if err != nil || key != ([32]byte(bytes.Repeat([]byte{0x91}, 32))) {
					t.Fatal("valid protected key rejected or transformed")
				}
				return
			}
			if !errors.Is(err, ErrInvalid) || key != ([32]byte{}) || strings.Contains(err.Error(), path) {
				t.Fatal("unsafe file returned material or filesystem diagnostics")
			}
		})
	}
}

func TestReadPrivateIdentityKeyScopedSymlinks(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		escapes bool
	}{
		{name: "projected mount"}, {name: "escape parent", escapes: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			target := filepath.Join(parent, "version", "key")
			if test.escapes {
				target = filepath.Join(t.TempDir(), "key")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x91}, 32))
			if err := os.WriteFile(target, []byte(encoded), 0o400); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "key")
			link := "version/key"
			if test.escapes {
				link = target
			}
			if err := os.Symlink(link, path); err != nil {
				t.Fatal(err)
			}
			key, err := (SecretFile{path: path}).readPrivateIdentityKey(t.Context())
			if test.escapes {
				if !errors.Is(err, ErrInvalid) || key != ([32]byte{}) {
					t.Fatal("escaping link released material")
				}
				return
			}
			if err != nil || key[0] != 0x91 {
				t.Fatal("safe projected link rejected")
			}
		})
	}
}

func TestReadPrivateIdentityKeyRejectsInvalidReferenceAndCancellation(t *testing.T) {
	t.Parallel()
	contextCanceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range []struct {
		name    string
		file    SecretFile
		context context.Context
	}{
		{name: "zero reference", context: t.Context()},
		{name: "nil context", file: SecretFile{path: "/keys/key"}},
		{name: "canceled", file: SecretFile{path: "/keys/key"}, context: contextCanceled},
		{name: "directory", file: SecretFile{path: t.TempDir()}, context: t.Context()},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			key, err := test.file.readPrivateIdentityKey(test.context)
			if !errors.Is(err, ErrInvalid) || key != ([32]byte{}) {
				t.Fatal("invalid call released material")
			}
		})
	}
}

func TestUnchangedPrivateKeyFileRejectsReplacementAndPermissionChange(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key")
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x91}, 32))
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if unchangedPrivateKeyFile(before, after) {
		t.Fatal("permission change accepted")
	}
	other := filepath.Join(filepath.Dir(path), "replacement")
	if err := os.WriteFile(other, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if unchangedPrivateKeyFile(before, replacement) || unchangedPrivateKeyFile(before, nil) {
		t.Fatal("file identity substitution accepted")
	}
}

func FuzzDecodePrivateIdentityKey(f *testing.F) {
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x91}, 32))
	for _, value := range []string{"", encoded, encoded + "\n", encoded + "\r\n", encoded + "=",
		encoded + "\n\n", strings.Repeat("A", 43), strings.Repeat("x", 46)} {
		f.Add([]byte(value))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		key, err := decodePrivateIdentityKey(input)
		if !bytes.Equal(input, before) {
			t.Fatal("decoder mutated caller input")
		}
		if err != nil {
			if !errors.Is(err, ErrInvalid) || key != ([32]byte{}) {
				t.Fatal("decoder released partial material")
			}
			return
		}
		if key == ([32]byte{}) {
			t.Fatal("decoder accepted zero material")
		}
		canonical := base64.RawURLEncoding.EncodeToString(key[:])
		if !bytes.Equal(input, []byte(canonical)) && !bytes.Equal(input, []byte(canonical+"\n")) &&
			!bytes.Equal(input, []byte(canonical+"\r\n")) {
			t.Fatal("decoder accepted noncanonical encoding")
		}
	})
}
