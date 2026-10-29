package privatefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotPublicDir reports a directory others could write into, or replace,
// that public files the service writes must not live in (K1e design §3.1).
var ErrNotPublicDir = errors.New("privatefile: not a safe public directory")

// PreparePublicDir creates dir, readable by every user and written only by
// the service (Unix 0755; Windows a protected DACL giving users read), when
// it is missing and its parent exists, then checks it as CheckPublicDir.
func PreparePublicDir(dir string, strict int) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		parent, statErr := os.Stat(filepath.Dir(dir))
		if statErr != nil || !parent.IsDir() {
			return fmt.Errorf("%w: the parent of %s must already exist", ErrNotPublicDir, dir)
		}
		if err := makePublicDir(dir); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	return CheckPublicDir(dir, strict)
}

// CheckPublicDir checks dir and the strict-1 directories above it strictly
// — real directories owned by the service or the system that nobody else
// may write into — and every directory above those as an ancestor nobody
// else may rename or replace a child of (K1e design §3.1, re-review H-b).
// A link above the strict levels (macOS /var) must belong to the system,
// sit in a directory that passes, and point into a chain that passes too
// (review e1b M1).
func CheckPublicDir(dir string, strict int) error {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || strict < 1 {
		return fmt.Errorf("%w: %s", ErrNotPublicDir, dir)
	}
	return checkChain(dir, strict, 0)
}

// maxLinkDepth bounds the links followed above the strict levels.
const maxLinkDepth = 8

func checkChain(path string, strict, depth int) error {
	if depth > maxLinkDepth {
		return fmt.Errorf("%w: too many links above %s", ErrNotPublicDir, path)
	}
	for level := 0; ; level++ {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrNotPublicDir, path, err)
		}
		if linksAllowed && level >= strict && info.Mode()&os.ModeSymlink != 0 {
			if err := checkLink(path, info); err != nil {
				return err
			}
			// One link at a time, so a link inside the target is checked
			// with its own directory too.
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("%w: reading %s: %w", ErrNotPublicDir, path, err)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(path), target)
			}
			if err := checkChain(filepath.Clean(target), 0, depth+1); err != nil {
				return err
			}
		} else if err := checkLevel(path, info, level < strict); err != nil {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func checkLevel(path string, info os.FileInfo, strict bool) error {
	if info.Mode().Type() != os.ModeDir || isReparsePoint(info) {
		return fmt.Errorf("%w: %s must be a directory, not a link", ErrNotPublicDir, path)
	}
	if strict {
		return checkStrictPublic(path, info)
	}
	return checkAncestor(path, info)
}
