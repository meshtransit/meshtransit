package k8sstate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"meshtransit.net/client/internal/privatefile"
)

// RestoreReport says what Restore did beyond writing the files, for the
// gateway to log.
type RestoreReport struct {
	// RemovedIdentities are identity records the directory held and the
	// Secret did not, such as after the Secret was recreated empty.
	RemovedIdentities []string
	// SkippedKeys are keys under prefixes this version does not know.
	SkippedKeys []string
}

// temporaryPrefixes are the temporary files the stores and Restore write
// before renaming; a killed process leaves them behind.
var temporaryPrefixes = []string{".identity-", ".profiles-", ".restore-"}

// Restore makes stateDir hold exactly the stores' files in data, a mirror's
// Data: the profile state and one record per identity. It runs before the
// stores open, so it writes the files itself rather than through them, and
// leaves other files in stateDir alone. Bad names under the stores' prefixes
// fail the restore; keys under other prefixes are skipped and reported.
func Restore(stateDir string, data map[string][]byte) (RestoreReport, error) {
	var report RestoreReport
	files := map[stateFile][]byte{}
	for key, value := range data {
		file, known, err := parseKey(key)
		if err != nil {
			return RestoreReport{}, err
		}
		if !known {
			report.SkippedKeys = append(report.SkippedKeys, key)
			continue
		}
		files[file] = value
	}
	slices.Sort(report.SkippedKeys)

	// Both directories are checked before anything is written.
	stateRoot, err := openPrivateDir(stateDir)
	if err != nil {
		return RestoreReport{}, err
	}
	defer func() { _ = stateRoot.Close() }()
	identityRoot, err := openPrivateDir(filepath.Join(stateDir, identityDir))
	if err != nil {
		return RestoreReport{}, err
	}
	defer func() { _ = identityRoot.Close() }()

	stateNames, err := listDir(stateRoot)
	if err != nil {
		return RestoreReport{}, err
	}
	if err := removeTemporaries(stateRoot, stateNames); err != nil {
		return RestoreReport{}, err
	}
	identityNames, err := listDir(identityRoot)
	if err != nil {
		return RestoreReport{}, err
	}
	if err := removeTemporaries(identityRoot, identityNames); err != nil {
		return RestoreReport{}, err
	}

	profileState, hasProfile := files[stateFile{name: profileFile}]
	if err := restoreFile(stateRoot, profileFile, profileState, hasProfile); err != nil {
		return RestoreReport{}, err
	}
	for _, name := range identityNames {
		if _, kept := files[stateFile{dir: identityDir, name: name}]; kept || !isIdentityFile(name) {
			continue
		}
		if err := restoreFile(identityRoot, name, nil, false); err != nil {
			return RestoreReport{}, err
		}
		report.RemovedIdentities = append(report.RemovedIdentities, name)
	}
	for file, value := range files {
		if file.dir == identityDir {
			if err := restoreFile(identityRoot, file.name, value, true); err != nil {
				return RestoreReport{}, err
			}
		}
	}
	return report, nil
}

func openPrivateDir(dir string) (*os.Root, error) {
	if err := privatefile.PrepareDir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("k8sstate: preparing %s: %w", dir, err)
	}
	if err := privatefile.RestrictDir(dir); err != nil {
		return nil, fmt.Errorf("k8sstate: restricting %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("k8sstate: opening %s: %w", dir, err)
	}
	return root, nil
}

// listDir lists root's entries through the root, sorted.
func listDir(root *os.Root) ([]string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("k8sstate: opening %s: %w", root.Name(), err)
	}
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("k8sstate: listing %s: %w", root.Name(), err)
	}
	slices.Sort(names)
	return names, nil
}

func removeTemporaries(root *os.Root, names []string) error {
	for _, name := range names {
		temporary := strings.HasSuffix(name, ".tmp") &&
			slices.ContainsFunc(temporaryPrefixes, func(prefix string) bool { return strings.HasPrefix(name, prefix) })
		if !temporary {
			continue
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("k8sstate: removing %s: %w", name, err)
		}
	}
	return nil
}

// restoreFile installs value as name in root, atomically and owner-only,
// or removes name when present is false. A link at name is replaced, never
// followed.
func restoreFile(root *os.Root, name string, value []byte, present bool) error {
	if !present {
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("k8sstate: removing %s: %w", name, err)
		}
		return privatefile.SyncDir(root)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("k8sstate: naming a temporary file: %w", err)
	}
	temporaryName := ".restore-" + hex.EncodeToString(suffix) + ".tmp"
	temporary, err := root.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("k8sstate: creating %s: %w", temporaryName, err)
	}
	defer func() {
		_ = temporary.Close()
		_ = root.Remove(temporaryName)
	}()
	if _, err := temporary.Write(value); err != nil {
		return fmt.Errorf("k8sstate: writing %s: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("k8sstate: syncing %s: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("k8sstate: closing %s: %w", name, err)
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("k8sstate: installing %s: %w", name, err)
	}
	return privatefile.SyncDir(root)
}
