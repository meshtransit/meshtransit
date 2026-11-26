package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func backupDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPendingCommitsAndPruneKeepsTheNewest(t *testing.T) {
	t.Parallel()
	dir := backupDir(t)
	const deployment = "01890f00-0000-7000-8000-000000000001"
	var names []string
	for day := range 4 {
		name := Name(deployment, time.Date(2026, 11, 20+day, 2, 15, 0, 0, time.UTC))
		pending, err := Create(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(pending, "backup "+name); err != nil {
			t.Fatal(err)
		}
		final, size, sum, err := pending.Commit()
		digest := sha256.Sum256([]byte("backup " + name))
		if err != nil || final != filepath.Join(dir, name) || size != int64(len("backup "+name)) ||
			sum != hex.EncodeToString(digest[:]) {
			t.Fatalf("commit = %s %d %s %v", final, size, sum, err)
		}
		names = append(names, name)
	}
	// Another Deployment's file, an unrelated file and a link are left alone.
	other := Name("01890f00-0000-7000-8000-000000000002", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	for _, name := range []string{other, "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, Name(deployment, time.Date(2026, 1, 1, 0, 0, 0, 0,
		time.UTC)))); err != nil {
		t.Fatal(err)
	}
	// A killed run's partial file is removed.
	abandoned, err := Create(dir, Name(deployment, time.Date(2026, 11, 25, 2, 15, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	_ = abandoned.file.Close()
	// A fresh partial (a run in progress) stays; an old one goes.
	if removed, err := Prune(dir, deployment, 2, names[3], time.Now()); err != nil || len(removed) != 2 ||
		removed[0] != names[0] || removed[1] != names[1] {
		t.Fatalf("removed %v %v", removed, err)
	}
	removed, err := Prune(dir, deployment, 2, names[3], time.Now().Add(6*time.Hour))
	if err != nil || len(removed) != 1 || !strings.HasSuffix(removed[0], ".partial") {
		t.Fatalf("removed %v %v", removed, err)
	}
	// A clock set back: the run just written sorts first but stays.
	early := Name(deployment, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err := os.WriteFile(filepath.Join(dir, early), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if removed, err := Prune(dir, deployment, 2, early, time.Now()); err != nil || len(removed) != 1 ||
		removed[0] != names[2] {
		t.Fatalf("clock set back: removed %v %v", removed, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	if len(left) != 5 || !strings.Contains(strings.Join(left, ","), names[3]) ||
		!strings.Contains(strings.Join(left, ","), early) {
		t.Fatalf("left %v", left)
	}
	if _, err := Prune(dir, deployment, 0, "", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Errorf("keep 0 accepted: %v", err)
	}
}

func TestCreateRefusesAnOpenDirectory(t *testing.T) {
	t.Parallel()
	dir := backupDir(t)
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- the case under test: an open directory.
		t.Fatal(err)
	}
	if _, err := Create(dir, Name("dep", time.Now())); !errors.Is(err, ErrInvalid) {
		t.Errorf("open directory: %v", err)
	}
	if _, err := Create("relative", Name("dep", time.Now())); !errors.Is(err, ErrInvalid) {
		t.Errorf("relative directory: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a private directory.
		t.Fatal(err)
	}
	if _, err := Create(dir, "../evil.mtbackup"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name: %v", err)
	}
}

func TestStatusAndMetrics(t *testing.T) {
	t.Parallel()
	dir, textfiles := backupDir(t), t.TempDir()
	if status, err := ReadStatus(dir); err != nil || !status.LastAttempt.IsZero() {
		t.Fatalf("empty status = %+v %v", status, err)
	}
	failed := Status{LastAttempt: time.Unix(1000, 0), LastResult: "backup_database_failed", Offsite: true}
	if err := WriteStatus(dir, textfiles, failed); err != nil {
		t.Fatal(err)
	}
	metrics, err := os.ReadFile(filepath.Join(textfiles, "meshtransit_backup.prom")) // #nosec G304 -- test directory.
	if err != nil {
		t.Fatal(err)
	}
	text := string(metrics)
	if !strings.Contains(text, "meshtransit_backup_last_result 0\n") || !strings.Contains(text, "meshtransit_backup_configured 1\n") ||
		strings.Contains(text, "last_success_timestamp") || !strings.Contains(text, "offsite_configured 1") ||
		strings.Contains(text, "offsite_last_success") {
		t.Fatalf("metrics after a failure:\n%s", text)
	}
	good := Status{LastAttempt: time.Unix(2000, 0), LastSuccess: time.Unix(2000, 0), LastResult: "ok", Size: 42,
		DurationSeconds: 1.5}
	if err := WriteStatus(dir, "", good); err != nil {
		t.Fatal(err)
	}
	read, err := ReadStatus(dir)
	if err != nil || read.LastResult != "ok" || read.Size != 42 {
		t.Fatalf("status = %+v %v", read, err)
	}
	if text := Metrics(good); !strings.Contains(text, "meshtransit_backup_last_success_timestamp_seconds 2000\n") ||
		!strings.Contains(text, "meshtransit_backup_last_result 1\n") {
		t.Fatalf("metrics:\n%s", text)
	}
}

func TestS3UploadSignsOnePut(t *testing.T) {
	t.Parallel()
	var seen *http.Request
	var body string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		seen, body = r, string(data)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	dir := t.TempDir()
	credentials := filepath.Join(dir, "s3")
	if err := os.WriteFile(credentials, []byte("# backup bucket\nACCESS_KEY_ID=AKIDEXAMPLE\nSECRET_ACCESS_KEY=secret\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, Name("dep-1", time.Date(2026, 11, 26, 2, 15, 0, 0, time.UTC)))
	if err := os.WriteFile(file, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("encrypted"))
	target := S3{Endpoint: server.URL, Region: "auto", Bucket: "backups", Prefix: "/meshtransit/",
		CredentialsFile: credentials, Client: server.Client()}
	if err := target.Upload(context.Background(), "dep-1", file, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if seen.Method != http.MethodPut || seen.URL.Path != "/backups/meshtransit/dep-1/"+filepath.Base(file) ||
		body != "encrypted" || !strings.HasPrefix(seen.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") ||
		seen.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(digest[:]) {
		t.Fatalf("request %s %s %q %v", seen.Method, seen.URL.Path, body, seen.Header)
	}
	for name, endpoint := range map[string]string{"http": "http://x", "path": "https://x/y", "user": "https://u@x"} {
		if _, err := (S3{Endpoint: endpoint, Bucket: "b"}).ObjectURL("d", "n"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s endpoint accepted: %v", name, err)
		}
	}
	if err := os.WriteFile(credentials, []byte("ACCESS_KEY_ID=only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadS3Credentials(credentials); !errors.Is(err, ErrInvalid) {
		t.Errorf("half a credential accepted: %v", err)
	}
}
