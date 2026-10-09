package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	manifestSchemaVersion = "meshtransit.dex-patch/v1"
	dexUpstreamRepository = "https://github.com/dexidp/dex.git"
	dexUpstreamModule     = "github.com/dexidp/dex"
	maximumManifestBytes  = 1 << 20
)

var (
	errInvalidManifest   = errors.New("dex artifact verifier: invalid manifest")
	hexSHA256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionPattern       = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	moduleVersionPattern = regexp.MustCompile(`^v0\.0\.0-[0-9]{14}-[0-9a-f]{12}$`)
	patchIDPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	goVersionPattern     = regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+$`)
)

type artifactManifest struct {
	SchemaVersion    string             `json:"schema_version"`
	Upstream         upstreamReference  `json:"upstream"`
	Patches          []patchReference   `json:"patches"`
	SourceTreeSHA256 string             `json:"source_tree_sha256"`
	Build            buildReference     `json:"build"`
	Evidence         evidenceReferences `json:"evidence"`
}

type upstreamReference struct {
	Repository    string `json:"repository"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	ModulePath    string `json:"module_path"`
	ModuleVersion string `json:"module_version"`
}

type patchReference struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type buildReference struct {
	GoVersion    string   `json:"go_version"`
	Flags        []string `json:"flags"`
	BinarySHA256 string   `json:"binary_sha256"`
}

type evidenceReferences struct {
	LicenseInventory    fileReference `json:"license_inventory"`
	SBOM                fileReference `json:"sbom"`
	VulnerabilityReport fileReference `json:"vulnerability_report"`
	QualificationReport fileReference `json:"qualification_report"`
}

type fileReference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type loadedManifest struct {
	manifest artifactManifest
	root     *os.Root
}

func loadManifest(manifestPath string) (loadedManifest, error) {
	absolutePath, err := regularAbsolutePath(manifestPath)
	if err != nil {
		return loadedManifest{}, errInvalidManifest
	}
	data, err := readBoundedFile(absolutePath, maximumManifestBytes)
	if err != nil {
		return loadedManifest{}, errInvalidManifest
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return loadedManifest{}, errInvalidManifest
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	manifest := artifactManifest{}
	if err := decoder.Decode(&manifest); err != nil {
		return loadedManifest{}, errInvalidManifest
	}
	if err := requireJSONEOF(decoder); err != nil {
		return loadedManifest{}, errInvalidManifest
	}
	if err := manifest.validate(); err != nil {
		return loadedManifest{}, err
	}

	root, err := os.OpenRoot(filepath.Dir(absolutePath))
	if err != nil {
		return loadedManifest{}, errInvalidManifest
	}
	return loadedManifest{manifest: manifest, root: root}, nil
}

func (loaded loadedManifest) close() error {
	if loaded.root == nil {
		return nil
	}
	return loaded.root.Close()
}

func (manifest artifactManifest) validate() error {
	if manifest.SchemaVersion != manifestSchemaVersion ||
		manifest.Upstream.Repository != dexUpstreamRepository ||
		manifest.Upstream.ModulePath != dexUpstreamModule ||
		!versionPattern.MatchString(manifest.Upstream.Version) ||
		!commitPattern.MatchString(manifest.Upstream.Commit) ||
		!moduleVersionPattern.MatchString(manifest.Upstream.ModuleVersion) ||
		!strings.HasSuffix(manifest.Upstream.ModuleVersion, "-"+manifest.Upstream.Commit[:12]) ||
		!hexSHA256Pattern.MatchString(manifest.SourceTreeSHA256) ||
		!goVersionPattern.MatchString(manifest.Build.GoVersion) ||
		!hexSHA256Pattern.MatchString(manifest.Build.BinarySHA256) ||
		len(manifest.Patches) == 0 || len(manifest.Patches) > 32 ||
		len(manifest.Build.Flags) == 0 || len(manifest.Build.Flags) > 64 {
		return errInvalidManifest
	}

	patchIDs := make(map[string]struct{}, len(manifest.Patches))
	paths := make(map[string]struct{}, len(manifest.Patches)+4)
	for _, patch := range manifest.Patches {
		if !patchIDPattern.MatchString(patch.ID) || !validRelativePath(patch.Path) ||
			!hexSHA256Pattern.MatchString(patch.SHA256) {
			return errInvalidManifest
		}
		if _, duplicate := patchIDs[patch.ID]; duplicate {
			return errInvalidManifest
		}
		if _, duplicate := paths[patch.Path]; duplicate {
			return errInvalidManifest
		}
		patchIDs[patch.ID] = struct{}{}
		paths[patch.Path] = struct{}{}
	}
	for _, buildFlag := range manifest.Build.Flags {
		if !validBoundedText(buildFlag, 256) {
			return errInvalidManifest
		}
	}

	references := [...]fileReference{
		manifest.Evidence.LicenseInventory,
		manifest.Evidence.SBOM,
		manifest.Evidence.VulnerabilityReport,
		manifest.Evidence.QualificationReport,
	}
	for _, reference := range references {
		if !validRelativePath(reference.Path) || !hexSHA256Pattern.MatchString(reference.SHA256) {
			return errInvalidManifest
		}
		if _, duplicate := paths[reference.Path]; duplicate {
			return errInvalidManifest
		}
		paths[reference.Path] = struct{}{}
	}
	return nil
}

func validRelativePath(value string) bool {
	return value != "" && len(value) <= 512 && filepath.IsLocal(value) &&
		filepath.ToSlash(value) == value && path.Clean(value) == value && value != "."
}

func validBoundedText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func regularAbsolutePath(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errInvalidOptions
	}
	info, err := os.Lstat(value)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errInvalidOptions
	}
	return value, nil
}

func executableAbsolutePath(value string) (string, error) {
	absolutePath, err := regularAbsolutePath(value)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absolutePath)
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		return "", errInvalidOptions
	}
	return absolutePath, nil
}

func directoryAbsolutePath(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errInvalidOptions
	}
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		return "", errInvalidOptions
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errInvalidOptions
	}
	return resolved, nil
}

func emptyDirectoryAbsolutePath(value string) (string, error) {
	absolutePath, err := directoryAbsolutePath(value)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(absolutePath)
	if err != nil || len(entries) != 0 {
		return "", errInvalidOptions
	}
	return absolutePath, nil
}

func readBoundedFile(filePath string, maximum int64) ([]byte, error) {
	file, err := os.Open(filePath) // #nosec G304 -- callers validate an absolute regular file or a path inside the private verification checkout.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds maximum size")
	}
	return data, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errInvalidManifest
	}
	return nil
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errInvalidManifest
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			nameToken, nameErr := decoder.Token()
			if nameErr != nil {
				return errInvalidManifest
			}
			name, ok := nameToken.(string)
			if !ok {
				return errInvalidManifest
			}
			if _, duplicate := names[name]; duplicate {
				return errInvalidManifest
			}
			names[name] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidManifest
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidManifest
		}
	default:
		return errInvalidManifest
	}
	return nil
}
