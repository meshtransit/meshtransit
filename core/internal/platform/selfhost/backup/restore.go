package backup

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

const (
	maxManifest = 64 << 20
	// maxMembers bounds the archive's member count (a one-server database
	// has a few thousand files).
	maxMembers = 1 << 20
	// maxWindow bounds zstd's window (the writer uses the default 8 MiB).
	maxWindow = 64 << 20
)

// Expect is what a backup must match to be restored here.
type Expect struct {
	DeploymentID string
	// CoreVersion and CoreRevision are the running image's: a restore runs
	// with the backup's own image (newer code may not read older state as
	// it was, and the PostgreSQL it renders must own the data).
	CoreVersion  string
	CoreRevision string
	// AnyImage skips the image check: verifying a file's integrity with
	// another image is fine, restoring with it is not.
	AnyImage bool
	// PostgresMajor, when set, must be the backup's PG_VERSION: the
	// PostgreSQL this image runs must own the restored data.
	PostgresMajor string
}

// Verify reads a whole backup without writing anything: every member's
// SHA-256 against manifest.json, the database files against PostgreSQL's
// backup_manifest, every name against the archive's layout, and the
// manifest against expect. age does not authenticate the sender: anyone
// holding a recipient can make a file that decrypts, hence expect and the
// operator's out-of-band check of the file's SHA-256.
func Verify(in io.Reader, identities []age.Identity, expect Expect) (Manifest, error) {
	var manifest Manifest
	err := walk(in, identities, func(_ *tar.Header, name string, content io.Reader) error {
		if name == ManifestName {
			body, err := io.ReadAll(io.LimitReader(content, maxManifest+1))
			if err != nil {
				return fmt.Errorf("read manifest: %w", err)
			}
			if len(body) > maxManifest {
				return fmt.Errorf("%w: manifest too large", ErrInvalid)
			}
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			decoder.DisallowUnknownFields()
			return decoder.Decode(&manifest)
		}
		return nil
	}, nil)
	if err != nil {
		return Manifest{}, err
	}
	return manifest, checkExpect(manifest, expect)
}

func checkExpect(manifest Manifest, expect Expect) error {
	if manifest.Format != Format {
		return fmt.Errorf("%w: format %d, this image reads %d", ErrInvalid, manifest.Format, Format)
	}
	if expect.DeploymentID == "" || manifest.Meta.DeploymentID != expect.DeploymentID {
		return fmt.Errorf("%w: backup of Deployment %q, expected %q", ErrInvalid, manifest.Meta.DeploymentID,
			expect.DeploymentID)
	}
	if !expect.AnyImage && (expect.CoreVersion == "" || manifest.Meta.CoreVersion != expect.CoreVersion ||
		manifest.Meta.CoreRevision != expect.CoreRevision) {
		return fmt.Errorf("%w: made by Core %s (%s); restore with that image, not %s (%s)", ErrInvalid,
			manifest.Meta.CoreVersion, manifest.Meta.CoreRevision, expect.CoreVersion, expect.CoreRevision)
	}
	if expect.PostgresMajor != "" && manifest.Postgres.Version != expect.PostgresMajor {
		return fmt.Errorf("%w: PostgreSQL %s data; this image runs PostgreSQL %s", ErrInvalid,
			manifest.Postgres.Version, expect.PostgresMajor)
	}
	return nil
}

// walk decrypts and reads the archive, calling visit for each member after
// checking its name and type. It checks every member's SHA-256 against the
// manifest read last, PostgreSQL's files against backup_manifest, and that
// nothing follows the manifest. write, when set, receives each member's
// bytes as they are read (the second pass).
func walk(in io.Reader, identities []age.Identity,
	visit func(header *tar.Header, name string, content io.Reader) error,
	write func(header *tar.Header, name string) (io.WriteCloser, error),
) error {
	decrypted, err := age.Decrypt(in, identities...)
	if err != nil {
		return fmt.Errorf("%w: decrypt: %w", ErrInvalid, err)
	}
	decompressed, err := zstd.NewReader(decrypted, zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(maxWindow))
	if err != nil {
		return fmt.Errorf("%w: decompress: %w", ErrInvalid, err)
	}
	defer decompressed.Close()
	reader := tar.NewReader(decompressed)
	check := newPGCheck()
	seen := map[string]Member{}
	order := make([]string, 0, 1024)
	var manifest *Manifest
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		if manifest != nil {
			return fmt.Errorf("%w: %s follows the manifest", ErrInvalid, header.Name)
		}
		name, err := cleanName(header.Name)
		if err != nil {
			return err
		}
		if len(order) >= maxMembers {
			return fmt.Errorf("%w: more than %d members", ErrInvalid, maxMembers)
		}
		for key := range header.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse.") {
				return fmt.Errorf("%w: %s is a sparse file", ErrInvalid, name)
			}
		}
		member, err := readMember(header, name, reader, check, visit, write)
		if err != nil {
			return err
		}
		if name == ManifestName {
			manifest = member.manifest
			continue
		}
		if _, dup := seen[member.Name]; dup {
			return fmt.Errorf("%w: %s twice", ErrInvalid, member.Name)
		}
		seen[member.Name] = member.Member
		order = append(order, member.Name)
	}
	if manifest == nil {
		return fmt.Errorf("%w: no manifest (file cut short?)", ErrInvalid)
	}
	postgres, err := check.complete()
	if err != nil {
		return err
	}
	if manifest.Postgres != postgres {
		return fmt.Errorf("%w: manifest describes another database than the archive holds", ErrInvalid)
	}
	listed := map[string]bool{}
	for _, member := range manifest.Members {
		if listed[member.Name] {
			return fmt.Errorf("%w: manifest lists %s twice", ErrInvalid, member.Name)
		}
		listed[member.Name] = true
	}
	if names := SecretNames(manifest.Members); strings.Join(names, "\x00") != strings.Join(manifest.Secrets, "\x00") {
		return fmt.Errorf("%w: manifest's secrets do not match its members", ErrInvalid)
	}
	if len(manifest.Members) != len(order) {
		return fmt.Errorf("%w: manifest lists %d members, archive holds %d", ErrInvalid, len(manifest.Members),
			len(order))
	}
	for _, listed := range manifest.Members {
		if seen[listed.Name] != listed {
			return fmt.Errorf("%w: %s does not match the manifest", ErrInvalid, listed.Name)
		}
	}
	return nil
}

type readResult struct {
	Member
	manifest *Manifest
}

func readMember(header *tar.Header, name string, reader io.Reader, check *pgCheck,
	visit func(*tar.Header, string, io.Reader) error,
	write func(*tar.Header, string) (io.WriteCloser, error),
) (readResult, error) {
	switch header.Typeflag {
	case tar.TypeDir:
		if name == ManifestName {
			return readResult{}, fmt.Errorf("%w: manifest is a directory", ErrInvalid)
		}
		if write != nil {
			if _, err := write(header, name+"/"); err != nil {
				return readResult{}, err
			}
		}
		return readResult{Member: Member{Name: name + "/"}}, nil
	case tar.TypeReg:
	default:
		return readResult{}, fmt.Errorf("%w: %s has tar type %q", ErrInvalid, header.Name, header.Typeflag)
	}
	if header.Size < 0 || (!strings.HasPrefix(name, PostgresDir+"/") && header.Size > maxSmallFile &&
		name != ManifestName) {
		return readResult{}, fmt.Errorf("%w: %s is %d bytes", ErrInvalid, name, header.Size)
	}
	if name == ManifestName {
		body, err := io.ReadAll(io.LimitReader(reader, maxManifest+1))
		if err != nil || len(body) > maxManifest {
			return readResult{}, fmt.Errorf("%w: manifest unreadable or too large", ErrInvalid)
		}
		var manifest Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			return readResult{}, fmt.Errorf("%w: manifest: %w", ErrInvalid, err)
		}
		if visit != nil {
			if err := visit(header, name, strings.NewReader(string(body))); err != nil {
				return readResult{}, err
			}
		}
		return readResult{manifest: &manifest}, nil
	}
	digest := sha256.New()
	sinks := []io.Writer{digest}
	var finish func(int64) error
	if rest, ok := cutPrefix(name, PostgresDir+"/"); ok {
		sum, kept, done := check.file(rest)
		sinks = append(sinks, sum)
		if kept != nil {
			sinks = append(sinks, kept)
		}
		finish = done
	}
	var sink io.WriteCloser
	if write != nil {
		var err error
		if sink, err = write(header, name); err != nil {
			return readResult{}, err
		}
		sinks = append(sinks, sink)
	}
	written, err := io.Copy(io.MultiWriter(sinks...), reader)
	if sink != nil {
		if closeErr := sink.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return readResult{}, fmt.Errorf("read %s: %w", name, err)
	}
	if written != header.Size {
		return readResult{}, fmt.Errorf("%w: %s cut short", ErrInvalid, name)
	}
	if finish != nil {
		if err := finish(written); err != nil {
			return readResult{}, err
		}
	}
	if visit != nil {
		if err := visit(header, name, strings.NewReader("")); err != nil {
			return readResult{}, err
		}
	}
	return readResult{Member: Member{Name: name, Size: written, SHA256: hex.EncodeToString(digest.Sum(nil))}}, nil
}

// Placement decides where and how each top-level directory is written.
type Placement struct {
	Root     string      // existing, empty directory
	UID, GID int         // -1 keeps the process's
	DirMode  fs.FileMode // every directory
	FileMode fs.FileMode // the most a file may get: its archived mode is masked by it, owner read kept
}

// Extract is the second pass: it reads the backup again, writing each
// member under its directory's placement as it goes, with owner and mode
// set by the placement, never by the archive. Every write goes through an
// os.Root, so nothing can leave a placement even if its directory changes
// meanwhile. It checks the same hashes as Verify and fails if this read
// differs from the verified one (the file changed between the passes);
// what it wrote is then incomplete and the caller must discard it. Each
// placement's Root must exist and be empty.
func Extract(in io.Reader, identities []age.Identity, verified Manifest, expect Expect,
	placements map[string]Placement,
) error {
	roots := map[string]*placed{}
	defer func() {
		for _, root := range roots {
			_ = root.root.Close()
		}
	}()
	for _, top := range []string{PostgresDir, SecretsDir, OperatorDir, CaddyDataDir} {
		placement, ok := placements[top]
		if !ok {
			return fmt.Errorf("%w: no placement for %s", ErrInvalid, top)
		}
		entries, err := os.ReadDir(placement.Root)
		if err != nil {
			return fmt.Errorf("restore target %s: %w", top, err)
		}
		if len(entries) != 0 {
			return fmt.Errorf("%w: restore target for %s is not empty", ErrInvalid, top)
		}
		root, err := os.OpenRoot(placement.Root)
		if err != nil {
			return fmt.Errorf("restore target %s: %w", top, err)
		}
		roots[top] = &placed{root: root, placement: placement}
	}
	var read *Manifest
	err := walk(in, identities, func(_ *tar.Header, name string, content io.Reader) error {
		if name != ManifestName {
			return nil
		}
		var manifest Manifest
		if err := json.NewDecoder(content).Decode(&manifest); err != nil {
			return fmt.Errorf("%w: manifest: %w", ErrInvalid, err)
		}
		read = &manifest
		return nil
	}, func(header *tar.Header, name string) (io.WriteCloser, error) {
		return place(roots, header, name)
	})
	if err != nil {
		return err
	}
	if read == nil || !sameManifest(*read, verified) {
		return fmt.Errorf("%w: the file changed since it was verified", ErrInvalid)
	}
	for _, root := range roots {
		if err := syncDir(root.placement.Root); err != nil {
			return err
		}
	}
	return checkExpect(*read, expect)
}

type placed struct {
	root      *os.Root
	placement Placement
}

func sameManifest(a, b Manifest) bool {
	left, err1 := json.Marshal(a)
	right, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(left) == string(right)
}

// place creates one directory, or one file to write, inside its
// placement's root. Files are created exclusively.
func place(roots map[string]*placed, header *tar.Header, name string) (io.WriteCloser, error) {
	top, rest, _ := strings.Cut(strings.TrimSuffix(name, "/"), "/")
	target, ok := roots[top]
	if !ok || rest == "" {
		return nil, fmt.Errorf("%w: no placement for %s", ErrInvalid, name)
	}
	if parent := path.Dir(rest); parent != "." {
		if err := makeDirs(target, parent); err != nil {
			return nil, err
		}
	}
	if strings.HasSuffix(name, "/") {
		return nil, makeDirs(target, rest)
	}
	mode := permissions(header.Mode)&target.placement.FileMode | 0o400
	file, err := target.root.OpenFile(rest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("restore %s: %w", name, err)
	}
	if err := own(file, target.placement, mode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restore %s: %w", name, err)
	}
	return syncCloser{file}, nil
}

// makeDirs creates relative and its parents inside the root, each owned
// and moded by the placement.
func makeDirs(target *placed, relative string) error {
	current := ""
	for _, element := range strings.Split(relative, "/") {
		current = path.Join(current, element)
		if err := target.root.Mkdir(current, target.placement.DirMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("restore %s: %w", current, err)
		}
		directory, err := target.root.OpenFile(current, os.O_RDONLY|openDirOnly, 0)
		if err != nil {
			return fmt.Errorf("restore %s: %w", current, err)
		}
		err = own(directory, target.placement, target.placement.DirMode)
		_ = directory.Close()
		if err != nil {
			return fmt.Errorf("restore %s: %w", current, err)
		}
	}
	return nil
}

func own(file *os.File, placement Placement, mode fs.FileMode) error {
	if placement.UID >= 0 || placement.GID >= 0 {
		if err := file.Chown(placement.UID, placement.GID); err != nil {
			return err
		}
	}
	return file.Chmod(mode)
}

type syncCloser struct{ file *os.File }

func (closer syncCloser) Write(p []byte) (int, error) { return closer.file.Write(p) }

func (closer syncCloser) Close() error {
	if err := closer.file.Sync(); err != nil {
		_ = closer.file.Close()
		return err
	}
	return closer.file.Close()
}
