package privatefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotPrivate reports a state directory that is a link, not a directory,
// or owned by someone other than the service.
var ErrNotPrivate = errors.New("privatefile: not a private directory")

// PrepareDir creates dir with perm, owner-only on Windows whatever perm says,
// or checks the dir already there: a real directory, not a link or another
// reparse point, owned by the service. It never creates a chain of
// directories: dir's parent must already exist, so a mistyped or hostile path
// cannot make the service create directories on its way to being refused.
// Callers still restrict the directory afterwards.
func PrepareDir(dir string, perm os.FileMode) error {
	parent, err := os.Stat(filepath.Dir(dir))
	if err != nil {
		return fmt.Errorf("the parent of %s must already exist: %w", dir, err)
	}
	if !parent.IsDir() {
		return fmt.Errorf("the parent of %s is not a directory", dir)
	}
	if err := makeDir(dir, perm); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", dir, err)
	}
	if info.Mode().Type() != os.ModeDir || isReparsePoint(info) {
		return fmt.Errorf("%w: %s must be a directory, not a link", ErrNotPrivate, dir)
	}

	return checkDirOwner(dir, info)
}
