//go:build windows

package privatefile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// restrictedSDDL is owned by Administrators with a protected DACL that
// gives SYSTEM and Administrators full control, inherited by new files and
// subdirectories, and nobody else any access.
const restrictedSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// CheckFile rejects a file whose owner is not SYSTEM or Administrators or
// whose DACL grants anyone else access. A missing DACL grants everyone.
func CheckFile(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading the security of %s: %w", path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("reading the owner of %s: %w", path, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("reading the access list of %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%w: %s has no access list", ErrTooBroad, path)
	}
	allowed := make([]string, 0, dacl.AceCount)
	for index := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("reading the access list of %s: %w", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		// The SID starts at SidStart inside the variable-length ACE.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows ACE layout.
		allowed = append(allowed, sid.String())
	}
	if !trustedSIDs(owner.String(), allowed) {
		return fmt.Errorf("%w: %s grants access beyond SYSTEM and Administrators", ErrTooBroad, path)
	}

	return nil
}

// RestrictDir gives dir a protected DACL for SYSTEM and Administrators that
// new files inherit.
func RestrictDir(dir string) error {
	descriptor, err := windows.SecurityDescriptorFromString(restrictedSDDL)
	if err != nil {
		return fmt.Errorf("building the access list for %s: %w", dir, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("building the access list for %s: %w", dir, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("building the access list for %s: %w", dir, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("restricting %s: %w", dir, err)
	}

	return nil
}

// SyncDir does nothing on Windows: NTFS journals directory metadata, and a
// directory handle cannot be flushed without write access to it.
func SyncDir(*os.Root) error { return nil }
