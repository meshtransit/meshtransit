//go:build windows

package privatefile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// publicSDDL is owned by Administrators with a protected DACL: SYSTEM and
// Administrators full control, Users and Authenticated Users read, list
// and traverse; new files inherit it.
const publicSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;AU)"

const sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// Access rights that let a holder write into, rename in, or take over a
// directory (K1e design §3.1).
const (
	rightWriteData       = 0x2 // FILE_WRITE_DATA, FILE_ADD_FILE
	rightAppendData      = 0x4 // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
	rightWriteEA         = 0x10
	rightDeleteChild     = 0x40
	rightWriteAttributes = 0x100
	rightDelete          = 0x10000
	rightWriteDAC        = 0x40000
	rightWriteOwner      = 0x80000
	rightGenericAll      = 0x10000000
	rightGenericWrite    = 0x40000000

	strictWrite = rightWriteData | rightAppendData | rightWriteEA | rightDeleteChild | rightWriteAttributes |
		rightDelete | rightWriteDAC | rightWriteOwner | rightGenericAll | rightGenericWrite
	// An ancestor may let users add files and folders, as C:\ and
	// C:\ProgramData do, but not rename, delete or take over what is in it
	// (DELETE on a directory and ADD_SUBDIRECTORY on its parent are enough
	// to replace it, review e1b M2).
	ancestorWrite = rightDelete | rightDeleteChild | rightWriteDAC | rightWriteOwner | rightGenericAll |
		rightGenericWrite
)

func makePublicDir(dir string) error {
	descriptor, err := windows.SecurityDescriptorFromString(publicSDDL)
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

func checkStrictPublic(path string, _ os.FileInfo) error {
	return checkACL(path, strictWrite, false)
}

func checkAncestor(path string, _ os.FileInfo) error {
	return checkACL(path, ancestorWrite, true)
}

// checkACL reads path's owner and DACL and checks them (checkDescriptor).
func checkACL(path string, forbidden uint32, ancestor bool) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: reading the security of %s: %w", ErrNotPublicDir, path, err)
	}
	return checkDescriptor(path, descriptor, forbidden, ancestor)
}

// ACE types by what they do (MS-DTYP 2.4.4.1).
const (
	aceAllowedCompound      = 0x4
	aceAllowedObject        = 0x5
	aceDeniedObject         = 0x6
	aceAllowedCallback      = 0x9
	aceDeniedCallback       = 0xA
	aceAllowedCallbackObj   = 0xB
	aceDeniedCallbackObject = 0xC
)

// checkDescriptor refuses a directory owned by someone untrusted, or whose
// DACL gives someone untrusted any of forbidden. Inherit-only entries do
// not apply to the directory itself. An allow entry other than the basic
// one (object, callback, compound) with any forbidden right refuses
// whoever it names; deny entries never widen access; an entry of a type
// it does not know refuses a strict directory (review e1b M2).
func checkDescriptor(path string, descriptor *windows.SECURITY_DESCRIPTOR, forbidden uint32, ancestor bool) error {
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: reading the owner of %s", ErrNotPublicDir, path)
	}
	if !trustedPublic(owner.String(), ancestor) {
		return fmt.Errorf("%w: %s is owned by %s", ErrNotPublicDir, path, owner)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: %s has no access list", ErrNotPublicDir, path)
	}
	for index := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("%w: reading the access list of %s: %w", ErrNotPublicDir, path, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		mask := uint32(ace.Mask)
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows ACE layout.
			if mask&forbidden != 0 && !trustedPublic(sid.String(), ancestor) {
				return fmt.Errorf("%w: %s lets %s write", ErrNotPublicDir, path, sid)
			}
		case aceAllowedCompound, aceAllowedObject, aceAllowedCallback, aceAllowedCallbackObj:
			if mask&forbidden != 0 {
				return fmt.Errorf("%w: %s has a conditional or object entry that allows writing", ErrNotPublicDir,
					path)
			}
		case windows.ACCESS_DENIED_ACE_TYPE, aceDeniedObject, aceDeniedCallback, aceDeniedCallbackObject:
		default:
			if !ancestor {
				return fmt.Errorf("%w: %s has an access entry of type %d", ErrNotPublicDir, path,
					ace.Header.AceType)
			}
		}
	}
	return nil
}

// trustedPublic reports SYSTEM and Administrators, and TrustedInstaller on
// an ancestor.
func trustedPublic(sid string, ancestor bool) bool {
	return sid == sidLocalSystem || sid == sidAdministrators || ancestor && sid == sidTrustedInstaller
}

// linksAllowed is false: Windows' default paths have no link or junction,
// and whoever controls one decides where it points; checkLevel refuses it.
const linksAllowed = false

func checkLink(string, os.FileInfo) error { return nil }
