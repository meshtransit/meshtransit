package captive

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"meshtransit.net/client/internal/privatefile"
)

// openWindowFile opens the window file, a regular file in a directory only
// SYSTEM and administrators may change, letting others delete it while it
// is open: the service closes a window by deleting the file while the
// child that holds it reads it.
func openWindowFile(path string) (*os.File, error) {
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	if err := privatefile.CheckFile(filepath.Dir(path), nil); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWindowInvalid, err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWindowInvalid, err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: not a regular file", ErrWindowInvalid)
	}
	if err := privatefile.CheckFile(path, info); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %w", ErrWindowInvalid, err)
	}
	return file, nil
}
