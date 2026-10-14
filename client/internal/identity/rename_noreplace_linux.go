package identity

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames temporary to final inside root, atomically and
// only if final does not exist (renameat2 RENAME_NOREPLACE). Both are names
// in root's directory, never paths.
func renameNoReplace(root *os.Root, temporary, final string) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("opening the identity directory: %w", err)
	}
	defer func() { _ = directory.Close() }()
	descriptor := int(directory.Fd()) //nolint:gosec // a descriptor fits in an int
	err = unix.Renameat2(descriptor, temporary, descriptor, final, unix.RENAME_NOREPLACE)
	if err != nil {
		return &os.LinkError{Op: "renameat2", Old: temporary, New: final, Err: err}
	}
	return nil
}
