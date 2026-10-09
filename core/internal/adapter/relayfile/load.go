// Package relayfile loads one bounded product-owned relay directory snapshot.
package relayfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/relay"
)

const (
	// MaximumDocumentBytes bounds one complete operator-provided snapshot.
	MaximumDocumentBytes = 256 << 10
	digestPrefix         = "sha256:"
	maximumJSONDepth     = 8
	currentSchemaVersion = 1
)

// ErrInvalid reports an unsafe file, digest mismatch, malformed schema, or
// invalid directory without disclosing operator paths or topology.
var ErrInvalid = errors.New("relayfile: invalid directory")

// ParseDigest parses one canonical non-zero SHA-256 file digest.
func ParseDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !strings.HasPrefix(value, digestPrefix) {
		return digest, ErrInvalid
	}
	encoded := strings.TrimPrefix(value, digestPrefix)
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size || digestPrefix+hex.EncodeToString(decoded) != value {
		return digest, ErrInvalid
	}
	copy(digest[:], decoded)
	if digest == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return digest, nil
}

// Decode verifies and decodes one bounded product-owned snapshot.
func Decode(reader io.Reader, expected [sha256.Size]byte) (relay.Directory, error) {
	if reader == nil || expected == ([sha256.Size]byte{}) {
		return relay.Directory{}, ErrInvalid
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumDocumentBytes+1))
	if err != nil {
		return relay.Directory{}, ErrInvalid
	}
	defer clear(encoded)
	return decode(encoded, expected)
}

// Load reads a regular, non-group-writable local snapshot confined to its
// operator-selected parent and verifies it before returning domain state.
func Load(ctx context.Context, path string, expected [sha256.Size]byte) (relay.Directory, error) {
	validPath := ctx != nil && ctx.Err() == nil && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		len(path) > 0 && len(path) <= 4096
	if !validPath || expected == ([sha256.Size]byte{}) {
		return relay.Directory{}, ErrInvalid
	}
	// #nosec G304 -- the canonical operator path is confined to its selected parent.
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return relay.Directory{}, ErrInvalid
	}
	name := filepath.Base(path)
	file, err := openDirectoryFile(root, name)
	if err != nil {
		_ = root.Close()
		return relay.Directory{}, ErrInvalid
	}
	before, statErr := file.Stat()
	if statErr != nil || !validFileInfo(before) {
		_ = file.Close()
		_ = root.Close()
		return relay.Directory{}, ErrInvalid
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, MaximumDocumentBytes+1))
	after, afterErr := file.Stat()
	current, currentErr := root.Stat(name)
	fileCloseErr := file.Close()
	rootCloseErr := root.Close()
	defer clear(encoded)
	if readErr != nil || afterErr != nil || currentErr != nil || fileCloseErr != nil || rootCloseErr != nil ||
		ctx.Err() != nil || !unchangedFile(before, after) || !unchangedFile(after, current) ||
		int64(len(encoded)) != before.Size() {
		return relay.Directory{}, ErrInvalid
	}
	return decode(encoded, expected)
}

func decode(encoded []byte, expected [sha256.Size]byte) (relay.Directory, error) {
	if len(encoded) == 0 || len(encoded) > MaximumDocumentBytes {
		return relay.Directory{}, ErrInvalid
	}
	actual := sha256.Sum256(encoded)
	if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 || validateUniqueNames(encoded) != nil {
		return relay.Directory{}, ErrInvalid
	}
	var document directoryWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return relay.Directory{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return relay.Directory{}, ErrInvalid
	}
	return document.directory()
}

func validFileInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 &&
		info.Size() > 0 && info.Size() <= MaximumDocumentBytes
}

func unchangedFile(before, after os.FileInfo) bool {
	return validFileInfo(before) && validFileInfo(after) && os.SameFile(before, after) &&
		before.Mode() == after.Mode() && before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
}

type directoryWire struct {
	SchemaVersion *int         `json:"schema_version"`
	Revision      *uint64      `json:"revision"`
	Regions       []regionWire `json:"regions"`
}

type regionWire struct {
	ID    *int       `json:"id"`
	Code  *string    `json:"code"`
	Name  *string    `json:"name"`
	Nodes []nodeWire `json:"nodes"`
}

type nodeWire struct {
	Name       *string `json:"name"`
	HostName   *string `json:"host_name"`
	CertName   *string `json:"cert_name"`
	IPv4       *string `json:"ipv4"`
	IPv6       *string `json:"ipv6"`
	STUNPort   *int    `json:"stun_port"`
	RelayPort  *int    `json:"relay_port"`
	IsSTUNOnly *bool   `json:"stun_only"`
}

func (document directoryWire) directory() (relay.Directory, error) {
	if document.SchemaVersion == nil || *document.SchemaVersion != currentSchemaVersion ||
		document.Revision == nil || document.Regions == nil {
		return relay.Directory{}, ErrInvalid
	}
	regions := make([]relay.Region, 0, len(document.Regions))
	for _, candidate := range document.Regions {
		region, err := candidate.region()
		if err != nil {
			return relay.Directory{}, ErrInvalid
		}
		regions = append(regions, region)
	}
	directory, err := relay.NewDirectory(relay.DirectoryParams{
		Revision: *document.Revision,
		Regions:  regions,
	})
	if err != nil {
		return relay.Directory{}, ErrInvalid
	}
	return directory, nil
}

func (candidate regionWire) region() (relay.Region, error) {
	if candidate.ID == nil || candidate.Code == nil || candidate.Name == nil || candidate.Nodes == nil {
		return relay.Region{}, ErrInvalid
	}
	nodes := make([]relay.Node, 0, len(candidate.Nodes))
	for _, value := range candidate.Nodes {
		node, err := value.node()
		if err != nil {
			return relay.Region{}, ErrInvalid
		}
		nodes = append(nodes, node)
	}
	region, err := relay.NewRegion(relay.RegionParams{
		ID:    *candidate.ID,
		Code:  *candidate.Code,
		Name:  *candidate.Name,
		Nodes: nodes,
	})
	if err != nil {
		return relay.Region{}, ErrInvalid
	}
	return region, nil
}

func (candidate nodeWire) node() (relay.Node, error) {
	if candidate.Name == nil || candidate.HostName == nil || candidate.CertName == nil ||
		candidate.IPv4 == nil || candidate.IPv6 == nil || candidate.STUNPort == nil ||
		candidate.RelayPort == nil || candidate.IsSTUNOnly == nil {
		return relay.Node{}, ErrInvalid
	}
	node, err := relay.NewNode(relay.NodeParams{
		Name:       *candidate.Name,
		HostName:   *candidate.HostName,
		CertName:   *candidate.CertName,
		IPv4:       *candidate.IPv4,
		IPv6:       *candidate.IPv6,
		STUNPort:   *candidate.STUNPort,
		RelayPort:  *candidate.RelayPort,
		IsSTUNOnly: *candidate.IsSTUNOnly,
	})
	if err != nil {
		return relay.Node{}, ErrInvalid
	}
	return node, nil
}

func validateUniqueNames(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := scanValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func scanValue(decoder *json.Decoder, depth int) error {
	if depth > maximumJSONDepth {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			name, isName := nameToken.(string)
			canonical := strings.ToLower(name)
			if err != nil || !isName {
				return ErrInvalid
			}
			if _, duplicate := names[canonical]; duplicate {
				return ErrInvalid
			}
			names[canonical] = struct{}{}
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	if _, err := decoder.Token(); err != nil {
		return ErrInvalid
	}
	return nil
}
