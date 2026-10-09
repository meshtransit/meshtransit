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
	"strings"
	"testing"
	"time"
)

func TestNewPrivateIdentityKeyFilesRejectsInvalidProfile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*PrivateIdentityKeyOptions)
	}{
		{name: "missing required purpose", change: func(o *PrivateIdentityKeyOptions) { o.Capture = ResidentKeyFile{} }},
		{name: "same id", change: func(o *PrivateIdentityKeyOptions) { o.Capture.ID = o.Initiation.ID }},
		{name: "same path", change: func(o *PrivateIdentityKeyOptions) { o.Capture.File = o.Initiation.File }},
		{name: "relative path", change: func(o *PrivateIdentityKeyOptions) { o.Capture.File.path = "key" }},
		{name: "unclean path", change: func(o *PrivateIdentityKeyOptions) { o.Capture.File.path = "/keys/../key" }},
		{name: "long path", change: func(o *PrivateIdentityKeyOptions) { o.Capture.File.path = "/" + strings.Repeat("x", 4096) }},
		{name: "long id", change: func(o *PrivateIdentityKeyOptions) { o.Capture.ID = strings.Repeat("x", 65) }},
		{name: "id punctuation", change: func(o *PrivateIdentityKeyOptions) { o.Capture.ID = "capture.v1" }},
		{name: "id unicode", change: func(o *PrivateIdentityKeyOptions) { o.Capture.ID = "café" }},
		{name: "id leading hyphen", change: func(o *PrivateIdentityKeyOptions) { o.Capture.ID = "-capture" }},
		{name: "empty previous reference", change: func(o *PrivateIdentityKeyOptions) { o.SubjectPrevious = &ResidentKeyFile{} }},
		{name: "previous id alias", change: func(o *PrivateIdentityKeyOptions) { p := o.SubjectActive; o.SubjectPrevious = &p }},
		{name: "previous path alias", change: func(o *PrivateIdentityKeyOptions) { p := o.SessionActive; p.ID = "old"; o.SessionPrevious = &p }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := privateIdentityKeyOptionsFixture(t)
			test.change(&options)
			files, err := NewPrivateIdentityKeyFiles(options)
			if files != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}

func TestNewPrivateIdentityKeyFilesHasNoFileEffects(t *testing.T) {
	t.Parallel()
	options := privateIdentityKeyOptionsFixture(t)
	options.Capture.File = SecretFile{path: filepath.Join(t.TempDir(), "missing")}
	files, err := NewPrivateIdentityKeyFiles(options)
	if err != nil || files == nil {
		t.Fatal("constructor read a nonexistent file")
	}
	material, err := files.Load(t.Context())
	if material != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("missing file released a partial candidate")
	}
}

func TestPrivateIdentityKeyFilesLoadCompleteCandidate(t *testing.T) {
	t.Parallel()
	options := privateIdentityKeyOptionsFixture(t)
	files, err := NewPrivateIdentityKeyFiles(options)
	if err != nil {
		t.Fatalf("construct private key references: %v", err)
	}
	material, err := files.Load(t.Context())
	if err != nil {
		t.Fatalf("load private key candidate: %v", err)
	}
	defer material.Clear()
	if material.Initiation.ID != "initiation-v1" || material.Initiation.Bytes[0] != 1 ||
		material.RateLimit.Bytes[0] != 11 || material.SubjectPrevious != nil || material.SessionPrevious != nil {
		t.Fatal("loaded candidate does not match all required purposes")
	}
}

func TestPrivateIdentityKeyFilesRejectReusedMaterial(t *testing.T) {
	t.Parallel()
	options := privateIdentityKeyOptionsFixture(t)
	contents := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err := os.WriteFile(options.ManagementCSRF.File.path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := NewPrivateIdentityKeyFiles(options)
	if err != nil {
		t.Fatal(err)
	}
	material, err := files.Load(t.Context())
	if material != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("reused material released a partial or valid candidate")
	}
}

func TestPrivateIdentityKeyFilesCopyPreviousReferencesAndClear(t *testing.T) {
	t.Parallel()
	options := privateIdentityKeyOptionsFixture(t)
	previousSubject := privateIdentityPreviousFixture(t, "subject-v0", 12)
	previousSession := privateIdentityPreviousFixture(t, "session-v0", 13)
	options.SubjectPrevious, options.SessionPrevious = &previousSubject, &previousSession
	files, err := NewPrivateIdentityKeyFiles(options)
	if err != nil {
		t.Fatal(err)
	}
	previousSubject, previousSession = ResidentKeyFile{}, ResidentKeyFile{}
	material, err := files.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if material.SubjectPrevious == nil || material.SubjectPrevious.Bytes[0] != 12 ||
		material.SessionPrevious == nil || material.SessionPrevious.Bytes[0] != 13 {
		t.Fatal("caller mutation changed previous references")
	}
	subjectCopy, sessionCopy := material.SubjectPrevious, material.SessionPrevious
	material.Clear()
	if subjectCopy.Bytes != ([32]byte{}) || sessionCopy.Bytes != ([32]byte{}) ||
		subjectCopy.ID != "" || sessionCopy.ID != "" {
		t.Fatal("clear left previous material")
	}
	for _, key := range material.purposes() {
		if key != nil && (key.Bytes != ([32]byte{}) || key.ID != "") {
			t.Fatal("clear left current material")
		}
	}
	material.Clear()
	var absent *PrivateIdentityKeyMaterial
	absent.Clear()
}

func TestPrivateIdentityKeyFilesRejectPreviousMaterialAliases(t *testing.T) {
	t.Parallel()
	for _, fill := range []byte{1, 9, 12} {
		t.Run(fmt.Sprintf("previous alias %d", fill), func(t *testing.T) {
			t.Parallel()
			options := privateIdentityKeyOptionsFixture(t)
			subject := privateIdentityPreviousFixture(t, "subject-v0", 12)
			session := privateIdentityPreviousFixture(t, "session-v0", fill)
			options.SubjectPrevious, options.SessionPrevious = &subject, &session
			files, err := NewPrivateIdentityKeyFiles(options)
			if err != nil {
				t.Fatal(err)
			}
			material, err := files.Load(t.Context())
			if material != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("previous material alias released a candidate")
			}
		})
	}
}

func TestPrivateIdentityKeyFilesRejectInvalidOwnershipOrContext(t *testing.T) {
	t.Parallel()
	options := privateIdentityKeyOptionsFixture(t)
	files, err := NewPrivateIdentityKeyFiles(options)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, expire := context.WithDeadline(t.Context(), time.Unix(1, 0))
	defer expire()
	for _, test := range []struct {
		name    string
		files   *PrivateIdentityKeyFiles
		context context.Context
	}{
		{name: "nil owner", context: t.Context()},
		{name: "zero owner", files: &PrivateIdentityKeyFiles{}, context: t.Context()},
		{name: "nil context", files: files},
		{name: "canceled context", files: files, context: canceled},
		{name: "expired context", files: files, context: expired},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			material, err := test.files.Load(test.context)
			if material != nil || !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid owner or context released material")
			}
		})
	}
}

func TestPrivateIdentityKeyFilesWithholdsCandidateAfterEarlierFileRotation(t *testing.T) {
	t.Parallel()
	options := privateIdentityKeyOptionsFixture(t)
	files, err := NewPrivateIdentityKeyFiles(options)
	if err != nil {
		t.Fatal(err)
	}
	rotated := false
	material, err := files.loadCandidate(t.Context(), func(ctx context.Context, file SecretFile) ([32]byte, privateIdentityKeySnapshot, error) {
		key, snapshot, readErr := file.readPrivateIdentityKeySnapshot(ctx)
		if readErr != nil {
			return key, snapshot, readErr
		}
		if file == options.RateLimit.File {
			replacement := filepath.Join(filepath.Dir(options.Initiation.File.path), "replacement")
			encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
			if err := os.WriteFile(replacement, []byte(encoded), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, options.Initiation.File.path); err != nil {
				t.Fatal(err)
			}
			rotated = true
		}
		return key, snapshot, nil
	})
	if !rotated || material != nil || !errors.Is(err, ErrInvalid) {
		if material != nil {
			material.Clear()
		}
		t.Fatal("earlier file rotation released a mixed candidate")
	}
}

func TestPrivateIdentityKeyFilesWithholdsCandidateAfterReadFailureOrCancellation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		canceled bool
	}{
		{name: "last read failure"}, {name: "last read cancellation", canceled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := privateIdentityKeyOptionsFixture(t)
			files, err := NewPrivateIdentityKeyFiles(options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			material, err := files.loadCandidate(ctx, func(ctx context.Context, file SecretFile) ([32]byte, privateIdentityKeySnapshot, error) {
				key, snapshot, readErr := file.readPrivateIdentityKeySnapshot(ctx)
				if file == options.RateLimit.File {
					if test.canceled {
						cancel()
					} else {
						return key, snapshot, errors.New("private reader diagnostic")
					}
				}
				return key, snapshot, readErr
			})
			if material != nil || !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "private reader diagnostic") {
				t.Fatal("late reader failure/cancellation released partial material or raw diagnostics")
			}
		})
	}
}

func TestPrivateIdentityKeyDiagnosticsAreRedacted(t *testing.T) {
	t.Parallel()
	options := privateIdentityKeyOptionsFixture(t)
	files, err := NewPrivateIdentityKeyFiles(options)
	if err != nil {
		t.Fatal(err)
	}
	material, err := files.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	for _, value := range []any{options, &options, *files, files, *material, material,
		options.Initiation, material.Initiation} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != redactedValue {
				t.Fatal("format exposed key diagnostics")
			}
		}
		if _, err := json.Marshal(value); err == nil || strings.Contains(err.Error(), "initiation-v1") {
			t.Fatal("json accepted or disclosed key diagnostics")
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("private keys", "profile", value)
		if strings.Contains(logs.String(), "initiation-v1") || strings.Contains(logs.String(), options.Initiation.File.path) {
			t.Fatal("structured log disclosed key diagnostics")
		}
	}
}

func FuzzPrivateIdentityKeyID(f *testing.F) {
	for _, value := range []string{"", "key-v1", "key_v1", "-key", "key.v1", "café", strings.Repeat("a", 65)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !validPrivateIdentityKeyID(value) {
			return
		}
		if len(value) == 0 || len(value) > 64 || strings.TrimSpace(value) != value {
			t.Fatal("accepted unbounded or noncanonical id")
		}
		for index, character := range []byte(value) {
			isAlphaNumeric := character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
			if !isAlphaNumeric && (index == 0 || character != '-' && character != '_') {
				t.Fatal("accepted invalid id alphabet")
			}
		}
	})
}

func privateIdentityPreviousFixture(t *testing.T, id string, fill byte) ResidentKeyFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "previous.key")
	contents := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := NewSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return ResidentKeyFile{ID: id, File: file}
}

func privateIdentityKeyOptionsFixture(t *testing.T) PrivateIdentityKeyOptions {
	t.Helper()
	options := PrivateIdentityKeyOptions{}
	keys := []*ResidentKeyFile{
		&options.Initiation, &options.Capture, &options.Continuation, &options.ManagementCSRF,
		&options.TransactionDigest, &options.VerifierEncryption, &options.SubjectActive,
		&options.ProviderSession, &options.SessionActive, &options.Idempotency, &options.RateLimit,
	}
	names := []string{"initiation", "capture", "continuation", "csrf", "transaction", "verifier",
		"subject", "provider-session", "session", "idempotency", "rate-limit"}
	directory := t.TempDir()
	for index, key := range keys {
		path := filepath.Join(directory, names[index]+".key")
		contents := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := NewSecretFile(path)
		if err != nil {
			t.Fatal(err)
		}
		*key = ResidentKeyFile{ID: names[index] + "-v1", File: file}
	}
	return options
}
