package backup

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

var created = time.Date(2026, 11, 26, 2, 15, 0, 0, time.UTC)

func testMeta() Meta {
	return Meta{DeploymentID: "dep-1", Created: created, CoreVersion: "v1", CoreRevision: "abc",
		CoreImage: "core@sha256:1", PostgresImage: "postgres:18"}
}

func testExpect() Expect {
	return Expect{DeploymentID: "dep-1", CoreVersion: "v1", CoreRevision: "abc"}
}

type pgFile struct {
	name string
	data string
}

// pgStream builds a tar shaped like pg_basebackup -D - -Ft -X fetch: some
// directories, data files, WAL, and backup_manifest last. corrupt changes
// one listed checksum; omit leaves the manifest out.
func pgStream(t *testing.T, corrupt, omit bool) []byte {
	t.Helper()
	files := []pgFile{{"PG_VERSION", "18\n"}, {"base/1/PG_VERSION", "18\n"}, {"base/1/1259", "pages"},
		{"global/pg_control", "control"}, {"backup_label", "START WAL LOCATION"}}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, directory := range []string{"base/", "base/1/", "global/", "pg_wal/", "pg_notify/"} {
		if err := writer.WriteHeader(&tar.Header{Name: directory, Typeflag: tar.TypeDir, Mode: 0o700}); err != nil {
			t.Fatal(err)
		}
	}
	type listed struct {
		Path      string `json:"Path"`
		Size      int    `json:"Size"`
		Algorithm string `json:"Checksum-Algorithm"`
		Checksum  string `json:"Checksum"`
	}
	manifest := struct {
		Version  int      `json:"PostgreSQL-Backup-Manifest-Version"`
		SystemID uint64   `json:"System-Identifier"`
		Files    []listed `json:"Files"`
	}{Version: 2, SystemID: 7712333971829956657}
	for index, file := range files {
		if err := writer.WriteHeader(&tar.Header{Name: file.name, Typeflag: tar.TypeReg, Mode: 0o600,
			Size: int64(len(file.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(file.data)); err != nil {
			t.Fatal(err)
		}
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], crc32.Checksum([]byte(file.data), castagnoli))
		sum := hex.EncodeToString(encoded[:])
		if corrupt && index == 2 {
			sum = "00000000"
		}
		manifest.Files = append(manifest.Files, listed{file.name, len(file.data), "CRC32C", sum})
	}
	wal := "wal segment"
	if err := writer.WriteHeader(&tar.Header{Name: "pg_wal/000000010000000000000002", Typeflag: tar.TypeReg,
		Mode: 0o600, Size: int64(len(wal))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(wal)); err != nil {
		t.Fatal(err)
	}
	if !omit {
		body, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteHeader(&tar.Header{Name: "backup_manifest", Typeflag: tar.TypeReg, Mode: 0o600,
			Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type fixture struct {
	identity *age.X25519Identity
	secrets  string
	operator string
	caddy    string
	locked   int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	f := &fixture{identity: identity, secrets: filepath.Join(root, "secrets"), operator: filepath.Join(root, "etc"),
		caddy: filepath.Join(root, "caddy")}
	write := func(name, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(f.secrets, "state.json"), `{"format":"x"}`)
	write(filepath.Join(f.secrets, "account-session-digest.key"), "digest")
	write(filepath.Join(f.operator, "config.yaml"), "version: 1\n")
	write(filepath.Join(f.operator, "oidc", "client-secret"), "oidc")
	write(filepath.Join(f.caddy, "caddy", "certificates", "x.crt"), "cert")
	if err := os.Symlink("/etc/shadow", filepath.Join(f.caddy, "link")); err != nil {
		t.Fatal(err)
	}
	// A directory link and a FIFO a hostile Caddy could plant: left out,
	// and the FIFO must not hang the walk.
	if err := os.Symlink(f.secrets, filepath.Join(f.caddy, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(f.caddy, "caddy", "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) source(db []byte) Source {
	return Source{DB: bytes.NewReader(db), SecretsDir: f.secrets,
		Operator: []OperatorFile{{"config.yaml", filepath.Join(f.operator, "config.yaml")},
			{"oidc/client-secret", filepath.Join(f.operator, "oidc", "client-secret")}},
		CaddyDataDir: f.caddy, Lock: func() (func(), error) { f.locked++; return func() { f.locked-- }, nil }}
}

func (f *fixture) write(t *testing.T, db []byte) ([]byte, Result) {
	t.Helper()
	var out bytes.Buffer
	result, err := Write(&out, []age.Recipient{f.identity.Recipient()}, testMeta(), f.source(db))
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), result
}

func placements(t *testing.T) (map[string]Placement, string) {
	t.Helper()
	root := t.TempDir()
	result := map[string]Placement{}
	for _, top := range []string{PostgresDir, SecretsDir, OperatorDir, CaddyDataDir} {
		dir := filepath.Join(root, top)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		result[top] = Placement{Root: dir, UID: -1, GID: -1, DirMode: 0o700, FileMode: 0o600}
	}
	return result, root
}

func TestBackupRestoresWhatItArchived(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	file, result := f.write(t, pgStream(t, false, false))
	if f.locked != 0 {
		t.Fatal("lock not released")
	}
	if result.Skipped != 3 || result.Manifest.Postgres.Version != "18" ||
		result.Manifest.Postgres.SystemIdentifier != 7712333971829956657 || result.Manifest.Postgres.Files != 5 {
		t.Fatalf("result = %+v", result)
	}
	if strings.Join(result.Manifest.Secrets, ",") != "account-session-digest.key,state.json" {
		t.Fatalf("secrets = %v", result.Manifest.Secrets)
	}
	identities := []age.Identity{f.identity}
	manifest, err := Verify(bytes.NewReader(file), identities, testExpect())
	if err != nil {
		t.Fatal(err)
	}
	target, root := placements(t)
	if err := Extract(bytes.NewReader(file), identities, manifest, testExpect(), target); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{ // #nosec G101 -- archive member names and test contents.
		"postgres/PG_VERSION": "18\n", "postgres/base/1/1259": "pages", "postgres/pg_wal/000000010000000000000002": "wal segment",
		"postgres/backup_manifest": "", "secrets/state.json": `{"format":"x"}`, "operator/oidc/client-secret": "oidc",
		"caddy-data/caddy/certificates/x.crt": "cert",
	} {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name))) // #nosec G304 -- the test's own directory.
		if err != nil || (want != "" && string(got) != want) {
			t.Errorf("%s = %q, %v", name, got, err)
		}
	}
	if info, err := os.Stat(filepath.Join(root, "postgres", "pg_notify")); err != nil || !info.IsDir() {
		t.Errorf("empty database directory not restored: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "caddy-data", "link")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a link in Caddy's data was restored: %v", err)
	}
	for _, name := range []string{"dirlink", "caddy/fifo"} {
		if _, err := os.Lstat(filepath.Join(root, "caddy-data", name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("caddy-data/%s restored: %v", name, err)
		}
	}
	// A second extract into the same, now full, directories is refused.
	if err := Extract(bytes.NewReader(file), identities, manifest, testExpect(), target); !errors.Is(err, ErrInvalid) {
		t.Errorf("extract over restored data: %v", err)
	}
}

func TestBackupRefusesABadDatabaseStream(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for name, db := range map[string][]byte{
		"checksum":    pgStream(t, true, false),
		"no manifest": pgStream(t, false, true),
		"cut short":   pgStream(t, false, false)[:1024],
	} {
		var out bytes.Buffer
		_, err := Write(&out, []age.Recipient{f.identity.Recipient()}, testMeta(), f.source(db))
		if !errors.Is(err, ErrDatabase) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A link among the secrets is refused, not skipped.
	if err := os.Symlink("/etc/passwd", filepath.Join(f.secrets, "evil")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Write(&out, []age.Recipient{f.identity.Recipient()}, testMeta(), f.source(pgStream(t, false, false))); !errors.Is(err, ErrInvalid) {
		t.Errorf("link in secrets: %v", err)
	}
}

func TestVerifyRefusesTheWrongBackup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	file, _ := f.write(t, pgStream(t, false, false))
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bytes.NewReader(file), []age.Identity{other}, testExpect()); !errors.Is(err, ErrInvalid) {
		t.Errorf("wrong identity: %v", err)
	}
	for name, expect := range map[string]Expect{
		"deployment": {DeploymentID: "dep-2", CoreVersion: "v1", CoreRevision: "abc"},
		"image":      {DeploymentID: "dep-1", CoreVersion: "v2", CoreRevision: "def"},
		"empty":      {},
	} {
		if _, err := Verify(bytes.NewReader(file), []age.Identity{f.identity}, expect); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, cut := range map[string][]byte{"truncated": file[:len(file)/2], "flipped": flip(file)} {
		if _, err := Verify(bytes.NewReader(cut), []age.Identity{f.identity}, testExpect()); err == nil {
			t.Errorf("%s file verified", name)
		}
	}
}

func flip(file []byte) []byte {
	changed := append([]byte(nil), file...)
	changed[len(changed)-40] ^= 0xff
	return changed
}

// forge encrypts an arbitrary tar to the identity: what anyone holding the
// public recipient can do.
func forge(t *testing.T, identity *age.X25519Identity, members func(*tar.Writer)) []byte {
	t.Helper()
	var out bytes.Buffer
	encrypted, err := age.Encrypt(&out, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := zstd.NewWriter(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(compressed)
	members(writer)
	for _, closer := range []io.Closer{writer, compressed, encrypted} {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func TestVerifyRefusesForgedMembers(t *testing.T) {
	t.Parallel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	add := func(writer *tar.Writer, header *tar.Header, data string) {
		header.Size = int64(len(data))
		if header.Typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	for name, members := range map[string]func(*tar.Writer){
		"traversal": func(w *tar.Writer) { add(w, &tar.Header{Name: "secrets/../../etc/cron.d/x"}, "x") },
		"absolute":  func(w *tar.Writer) { add(w, &tar.Header{Name: "/etc/passwd"}, "x") },
		"outside":   func(w *tar.Writer) { add(w, &tar.Header{Name: "run/compose.yaml"}, "x") },
		"symlink": func(w *tar.Writer) {
			add(w, &tar.Header{Name: "secrets/k", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}, "")
		},
		"hardlink": func(w *tar.Writer) {
			add(w, &tar.Header{Name: "secrets/k", Typeflag: tar.TypeLink, Linkname: "/etc/shadow"}, "")
		},
		"after manifest": func(w *tar.Writer) {
			add(w, &tar.Header{Name: ManifestName}, `{"format":1}`)
			add(w, &tar.Header{Name: "secrets/k"}, "x")
		},
		"no manifest": func(w *tar.Writer) { add(w, &tar.Header{Name: "secrets/k"}, "x") },
	} {
		file := forge(t, identity, members)
		if _, err := Verify(bytes.NewReader(file), []age.Identity{identity}, testExpect()); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCleanName(t *testing.T) {
	t.Parallel()
	for name, ok := range map[string]bool{
		"postgres/base/1/1259": true, "postgres/base/": true, "manifest.json": true, "caddy-data/a/b": true,
		"postgres": false, "postgres/": false, "postgres/../x": false, "postgres/./x": false, "postgres//x": false,
		"/postgres/x": false, "other/x": false, "": false, "secrets/a\\b": false,
	} {
		if _, err := cleanName(name); (err == nil) != ok {
			t.Errorf("cleanName(%q) = %v, want ok %v", name, err, ok)
		}
	}
}

// TestRealBaseBackup runs on a real pg_basebackup -D - -Ft -X fetch stream
// when MESHTRANSIT_BACKUP_PG_STREAM names one, and leaves the restored data
// directory in MESHTRANSIT_BACKUP_PG_RESTORE (to start PostgreSQL on).
func TestRealBaseBackup(t *testing.T) {
	stream := os.Getenv("MESHTRANSIT_BACKUP_PG_STREAM")
	if stream == "" {
		t.Skip("MESHTRANSIT_BACKUP_PG_STREAM not set")
	}
	db, err := os.ReadFile(stream) // #nosec G304 G703 -- a test input the developer names.
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	file, result := f.write(t, db)
	t.Logf("postgres %+v, %d members, %d bytes encrypted", result.Manifest.Postgres, len(result.Manifest.Members),
		len(file))
	manifest, err := Verify(bytes.NewReader(file), []age.Identity{f.identity}, testExpect())
	if err != nil {
		t.Fatal(err)
	}
	target, root := placements(t)
	if out := os.Getenv("MESHTRANSIT_BACKUP_PG_RESTORE"); out != "" {
		target[PostgresDir] = Placement{Root: out, UID: -1, GID: -1, DirMode: 0o700, FileMode: 0o600}
	}
	if err := Extract(bytes.NewReader(file), []age.Identity{f.identity}, manifest, testExpect(), target); err != nil {
		t.Fatal(err)
	}
	_ = root
}
