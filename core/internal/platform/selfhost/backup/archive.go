package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// maxSmallFile bounds a file of secrets/, the operator's directory or
// Caddy's data, each read whole before it is archived (a file Caddy
// rewrites meanwhile is then archived whole or not at all).
const maxSmallFile = 16 << 20

// OperatorFile is a file of the operator's directory the backup carries:
// config.yaml and every file it names.
type OperatorFile struct {
	Name string // path relative to the operator's directory, kept on restore
	Path string
}

// Source is what one backup reads.
type Source struct {
	// DB is pg_basebackup's tar stream (-D - -Ft -X fetch).
	DB         io.Reader
	SecretsDir string
	Operator   []OperatorFile
	// CaddyDataDir is Caddy's data volume; empty skips it.
	CaddyDataDir string
	// Lock is held only while the files are read (not the database stream,
	// not the upload): setup runs may not change them meanwhile.
	Lock func() (func(), error)
}

// Result is what one written backup holds.
type Result struct {
	Manifest Manifest
	Skipped  int // links and special files found in Caddy's data, not archived
}

// Write streams one backup to out, encrypted to recipients. It reads the
// database stream first, checking it against its own backup_manifest, then
// the files under Lock, and writes manifest.json last.
func Write(out io.Writer, recipients []age.Recipient, meta Meta, source Source) (Result, error) {
	if len(recipients) == 0 || source.DB == nil || source.Lock == nil {
		return Result{}, fmt.Errorf("%w: recipients, database stream and lock are required", ErrInvalid)
	}
	encrypted, err := age.Encrypt(out, recipients...)
	if err != nil {
		return Result{}, fmt.Errorf("encrypt: %w", err)
	}
	compressed, err := zstd.NewWriter(encrypted, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return Result{}, fmt.Errorf("compress: %w", err)
	}
	archive := &archiveWriter{tar: tar.NewWriter(compressed), names: map[string]bool{}}
	manifest := Manifest{Format: Format, Meta: meta}
	if manifest.Postgres, err = archive.postgres(source.DB); err != nil {
		return Result{}, err
	}
	skipped, err := archive.files(source)
	if err != nil {
		return Result{}, err
	}
	manifest.Secrets = SecretNames(archive.members)
	manifest.Members = archive.members
	body, err := json.MarshalIndent(manifest, "", " ")
	if err != nil {
		return Result{}, fmt.Errorf("manifest: %w", err)
	}
	if err := archive.tar.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(body)),
		ModTime: meta.Created, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return Result{}, fmt.Errorf("write manifest: %w", err)
	}
	if _, err := archive.tar.Write(body); err != nil {
		return Result{}, fmt.Errorf("write manifest: %w", err)
	}
	for _, closer := range []io.Closer{archive.tar, compressed, encrypted} {
		if err := closer.Close(); err != nil {
			return Result{}, fmt.Errorf("finish backup: %w", err)
		}
	}
	return Result{Manifest: manifest, Skipped: skipped}, nil
}

type archiveWriter struct {
	tar     *tar.Writer
	members []Member
	names   map[string]bool
}

// add writes one member and records its size and SHA-256. A directory has
// a name ending in "/" and no content.
func (archive *archiveWriter) add(name string, mode fs.FileMode, modTime time.Time, size int64,
	content io.Reader, extra ...io.Writer,
) error {
	cleaned, err := cleanName(name)
	if err != nil {
		return err
	}
	directory := content == nil
	key := cleaned
	if directory {
		key += "/"
	}
	if archive.names[key] {
		return fmt.Errorf("%w: %s twice", ErrInvalid, key)
	}
	archive.names[key] = true
	header := &tar.Header{Name: key, Mode: int64(mode.Perm()), ModTime: modTime, Format: tar.FormatPAX}
	if directory {
		header.Typeflag = tar.TypeDir
	} else {
		header.Typeflag, header.Size = tar.TypeReg, size
	}
	if err := archive.tar.WriteHeader(header); err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	member := Member{Name: key}
	if !directory {
		digest := sha256.New()
		written, err := io.Copy(io.MultiWriter(append([]io.Writer{archive.tar, digest}, extra...)...), content)
		if err != nil {
			return fmt.Errorf("write %s: %w", key, err)
		}
		if written != size {
			return fmt.Errorf("%w: %s held %d bytes, header said %d", ErrInvalid, key, written, size)
		}
		member.Size, member.SHA256 = size, hex.EncodeToString(digest.Sum(nil))
	}
	archive.members = append(archive.members, member)
	return nil
}

// postgres copies the base backup member by member under postgres/.
func (archive *archiveWriter) postgres(stream io.Reader) (Postgres, error) {
	check := newPGCheck()
	reader := tar.NewReader(stream)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Postgres{}, fmt.Errorf("%w: %w", ErrDatabase, err)
		}
		name := path.Clean(header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := archive.add(PostgresDir+"/"+name, permissions(header.Mode), header.ModTime, 0, nil); err != nil {
				return Postgres{}, err
			}
		case tar.TypeReg:
			sum, kept, done := check.file(name)
			extra := []io.Writer{sum}
			if kept != nil {
				extra = append(extra, kept)
			}
			if err := archive.add(PostgresDir+"/"+name, permissions(header.Mode), header.ModTime, header.Size,
				reader, extra...); err != nil {
				return Postgres{}, err
			}
			if err := done(header.Size); err != nil {
				return Postgres{}, err
			}
		default:
			// A link or special file means tablespaces or a layout this
			// format does not restore.
			return Postgres{}, fmt.Errorf("%w: %s has tar type %q", ErrDatabase, header.Name, header.Typeflag)
		}
	}
	return check.complete()
}

// files archives secrets/, the operator's files and Caddy's data under the
// lock. It returns how many entries of Caddy's data it left out (links,
// special files, files gone meanwhile).
func (archive *archiveWriter) files(source Source) (int, error) {
	unlock, err := source.Lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if _, err := archive.tree(SecretsDir, source.SecretsDir, true); err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, file := range source.Operator {
		name := OperatorDir + "/" + file.Name
		if _, err := cleanName(name); err != nil || seen[name] {
			return 0, fmt.Errorf("%w: operator file %q (unsafe or twice)", ErrInvalid, file.Name)
		}
		seen[name] = true
		if err := archive.operatorFile(name, file.Path); err != nil {
			return 0, err
		}
	}
	if source.CaddyDataDir == "" {
		return 0, nil
	}
	return archive.tree(CaddyDataDir, source.CaddyDataDir, false)
}

// tree archives dir under prefix through an os.Root: no path, even one a
// container swaps for a link while the walk runs, leaves dir. Files open
// non-blocking (a FIFO cannot hang the run while the lock is held) and
// their type is checked on the open file. strict refuses a link, special
// file or vanished entry; otherwise (Caddy's data, which Caddy rewrites)
// they are counted and left out.
func (archive *archiveWriter) tree(prefix, dir string, strict bool) (int, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, fmt.Errorf("archive %s: %w", prefix, err)
	}
	defer func() { _ = root.Close() }()
	skipped := 0
	skip := func(err error) error {
		if strict {
			return err
		}
		skipped++
		return nil
	}
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Caddy's data: an entry gone meanwhile, or swapped for a link
			// that leaves the root, is left out rather than failing the run.
			if !strict && name != "." {
				skipped++
				return nil
			}
			return walkErr
		}
		if name == "." {
			return nil
		}
		switch {
		case entry.IsDir():
			info, err := entry.Info()
			if err != nil {
				return skip(err)
			}
			return archive.add(prefix+"/"+name, info.Mode(), info.ModTime(), 0, nil)
		case entry.Type().IsRegular():
			data, info, err := readSmall(root, name)
			if err != nil {
				if errors.Is(err, ErrInvalid) && strict {
					return err
				}
				return skip(err)
			}
			return archive.add(prefix+"/"+name, info.Mode(), info.ModTime(), int64(len(data)), bytes.NewReader(data))
		default:
			return skip(fmt.Errorf("%w: %s/%s is not a regular file", ErrInvalid, prefix, name))
		}
	})
	if err != nil {
		return 0, fmt.Errorf("archive %s: %w", prefix, err)
	}
	return skipped, nil
}

// readSmall reads one regular file of root whole, opened without blocking
// and its type checked on the open file. A link that stays inside the root
// is followed (os.Root resolves it; one leaving the root fails): the walk
// listed the entry as a regular file, so at worst another file of the same
// root is archived under this name.
func readSmall(root *os.Root, name string) ([]byte, fs.FileInfo, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|openSafely, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = file.Close() }()
	return readOpened(file, name)
}

func readOpened(file *os.File, name string) ([]byte, fs.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxSmallFile {
		return nil, nil, fmt.Errorf("%w: %s is not a regular file of at most %d bytes", ErrInvalid, name, maxSmallFile)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSmallFile+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(data) > maxSmallFile {
		return nil, nil, fmt.Errorf("%w: %s grew past %d bytes", ErrInvalid, name, maxSmallFile)
	}
	return data, info, nil
}

// operatorFile archives one file the operator names (the operator's
// directory is root's and read-only to every container).
func (archive *archiveWriter) operatorFile(name, location string) error {
	file, err := os.OpenFile(location, os.O_RDONLY|openSafely, 0) // #nosec G304 -- config.yaml's paths.
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = file.Close() }()
	data, info, err := readOpened(file, name)
	if err != nil {
		return err
	}
	return archive.add(name, info.Mode(), info.ModTime(), int64(len(data)), bytes.NewReader(data))
}

func cutPrefix(value, prefix string) (string, bool) {
	if len(value) < len(prefix) || value[:len(prefix)] != prefix {
		return "", false
	}
	return value[len(prefix):], true
}

// SecretNames are the top-level files of secrets/ among members.
func SecretNames(members []Member) []string {
	var names []string
	for _, member := range members {
		if rest, ok := cutPrefix(member.Name, SecretsDir+"/"); ok && member.SHA256 != "" && path.Dir(rest) == "." {
			names = append(names, rest)
		}
	}
	sort.Strings(names)
	return names
}

// permissions keeps a tar mode's permission bits only (never setuid,
// setgid, sticky or type bits).
func permissions(mode int64) fs.FileMode {
	return fs.FileMode(uint32(mode & 0o777)) // #nosec G115 -- masked to nine bits.
}
