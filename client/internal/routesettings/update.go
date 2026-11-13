package routesettings

import (
	"fmt"
	"path/filepath"
)

// Update changes the settings at path as one step against every other
// writer: under an exclusive lock it reads them (change gets the error of a
// file it could not read, ErrUnsafeFile included), writes what change
// returns, and returns that: under the lock it is what the file holds. Root's
// command and the
// helper's operator socket both write through it, so neither undoes what the
// other just wrote.
func Update(path string, change func(Settings, error) (Settings, error)) (Settings, error) {
	return update(path, Load, Save, change)
}

// UpdateExisting is Update for meshd changing the host's own choices on a
// caller's behalf: it never creates the settings directory or sets its
// access list, which a caller could otherwise make SYSTEM do; it changes
// the settings only inside a directory that exists already, private, no
// link, below directories nobody else may replace (ErrUnsafeFile).
func UpdateExisting(path string, change func(Settings, error) (Settings, error)) (Settings, error) {
	path = filepath.Clean(path)
	if err := checkExistingDirectory(filepath.Dir(path)); err != nil {
		return Settings{}, err
	}
	return lockedUpdate(path, Load, writeAtomically, change)
}

// update is Update with the file's reading and writing given.
func update(
	path string,
	load func(string) (Settings, error),
	save func(string, Settings) error,
	change func(Settings, error) (Settings, error),
) (Settings, error) {
	path = filepath.Clean(path)
	if err := prepareDirectory(filepath.Dir(path)); err != nil {
		return Settings{}, fmt.Errorf("routesettings: preparing %s: %w", filepath.Dir(path), err)
	}
	return lockedUpdate(path, load, save, change)
}

// lockedUpdate reads, changes and writes the settings under the lock.
func lockedUpdate(
	path string,
	load func(string) (Settings, error),
	save func(string, Settings) error,
	change func(Settings, error) (Settings, error),
) (Settings, error) {
	unlock, err := lockSettings(path)
	if err != nil {
		return Settings{}, err
	}
	defer unlock()
	current, loadErr := load(path)
	changed, err := change(current, loadErr)
	if err != nil {
		return Settings{}, err
	}
	if err := save(path, changed); err != nil {
		return Settings{}, err
	}
	return changed.Canonical(), nil
}
