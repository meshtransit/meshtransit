package backup

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"hash/crc32"
	"strings"
)

// maxBackupManifest bounds PostgreSQL's backup_manifest kept in memory (one
// line per data file; a one-server database has a few thousand).
const maxBackupManifest = 64 << 20

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// pgCheck follows a pg_basebackup tar stream (-Ft -X fetch, written to
// stdout): the CRC32C of every data file, PG_VERSION, and backup_manifest,
// which PostgreSQL writes last. Complete compares them: a stream cut short
// (even at a member boundary) lacks the manifest or some of its files.
type pgCheck struct {
	sums     map[string]fileSum
	manifest []byte
	version  string
}

type fileSum struct {
	size int64
	crc  uint32
}

func newPGCheck() *pgCheck { return &pgCheck{sums: map[string]fileSum{}} }

// file returns the hash to feed with the member's bytes and a function to
// call once they are all written.
func (check *pgCheck) file(name string) (hash.Hash32, *capture, func(size int64) error) {
	sum := crc32.New(castagnoli)
	var kept *capture
	switch name {
	case "backup_manifest":
		kept = &capture{limit: maxBackupManifest}
	case "PG_VERSION":
		kept = &capture{limit: 64}
	}
	return sum, kept, func(size int64) error {
		if kept != nil {
			if kept.overflow {
				return fmt.Errorf("%w: %s too large", ErrDatabase, name)
			}
			switch name {
			case "backup_manifest":
				check.manifest = kept.data
				return nil // not listed in itself
			case "PG_VERSION":
				check.version = strings.TrimSpace(string(kept.data))
			}
		}
		if _, seen := check.sums[name]; seen {
			return fmt.Errorf("%w: %s twice", ErrDatabase, name)
		}
		check.sums[name] = fileSum{size: size, crc: sum.Sum32()}
		return nil
	}
}

// pgManifest is the part of PostgreSQL's backup_manifest (version 1 or 2)
// the check reads.
type pgManifest struct {
	Version          int    `json:"PostgreSQL-Backup-Manifest-Version"`
	SystemIdentifier uint64 `json:"System-Identifier"`
	Files            []struct {
		Path      string `json:"Path"`
		Size      int64  `json:"Size"`
		Algorithm string `json:"Checksum-Algorithm"`
		Checksum  string `json:"Checksum"`
	} `json:"Files"`
}

// complete checks every file backup_manifest lists against what the stream
// held. PostgreSQL writes a CRC32C as the hex of its little-endian bytes.
func (check *pgCheck) complete() (Postgres, error) {
	if check.manifest == nil {
		return Postgres{}, fmt.Errorf("%w: no backup_manifest (stream cut short?)", ErrDatabase)
	}
	if check.version == "" {
		return Postgres{}, fmt.Errorf("%w: no PG_VERSION", ErrDatabase)
	}
	var manifest pgManifest
	if err := json.Unmarshal(check.manifest, &manifest); err != nil {
		return Postgres{}, fmt.Errorf("%w: backup_manifest: %w", ErrDatabase, err)
	}
	if manifest.Version < 1 || manifest.Version > 2 || len(manifest.Files) == 0 {
		return Postgres{}, fmt.Errorf("%w: backup_manifest version %d with %d files", ErrDatabase,
			manifest.Version, len(manifest.Files))
	}
	for _, listed := range manifest.Files {
		if listed.Algorithm != "CRC32C" {
			return Postgres{}, fmt.Errorf("%w: %s checksum %q, want CRC32C", ErrDatabase, listed.Path, listed.Algorithm)
		}
		got, found := check.sums[listed.Path]
		if !found {
			return Postgres{}, fmt.Errorf("%w: %s missing from the stream", ErrDatabase, listed.Path)
		}
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], got.crc)
		if got.size != listed.Size || hex.EncodeToString(encoded[:]) != strings.ToLower(listed.Checksum) {
			return Postgres{}, fmt.Errorf("%w: %s does not match backup_manifest", ErrDatabase, listed.Path)
		}
	}
	return Postgres{Version: check.version, SystemIdentifier: manifest.SystemIdentifier,
		Files: len(manifest.Files)}, nil
}

// capture keeps up to limit bytes written to it.
type capture struct {
	limit    int
	data     []byte
	overflow bool
}

func (kept *capture) Write(p []byte) (int, error) {
	if len(kept.data)+len(p) > kept.limit {
		kept.overflow = true
		return len(p), nil
	}
	kept.data = append(kept.data, p...)
	return len(p), nil
}
