//go:build windows

package privatefile

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// makeDir creates dir with the restricted access list from the start, so
// there is no moment when it inherits a parent that lets users write, such
// as C:\ProgramData.
func makeDir(dir string, _ os.FileMode) error {
	descriptor, err := windows.SecurityDescriptorFromString(restrictedSDDL)
	if err != nil {
		return fmt.Errorf("building the access list for %s: %w", dir, err)
	}
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	if err := windows.CreateDirectory(path, &attributes); err != nil {
		if err == windows.ERROR_ALREADY_EXISTS { //nolint:errorlint // CreateDirectory returns the bare Errno.
			return os.ErrExist
		}
		return err
	}

	return nil
}

// isReparsePoint reports junctions and mount points as well as symbolic
// links: following one would put the service's files somewhere else.
func isReparsePoint(info os.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)

	return !ok || data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// checkDirOwner requires SYSTEM or Administrators to own the directory: a
// directory a user created first keeps that user as owner, who could change
// its access list back.
func checkDirOwner(dir string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading the owner of %s: %w", dir, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("reading the owner of %s: %w", dir, err)
	}
	if !trustedSIDs(owner.String(), nil) {
		return fmt.Errorf("%w: %s is owned by %s, not SYSTEM or Administrators", ErrNotPrivate, dir, owner)
	}

	return nil
}
