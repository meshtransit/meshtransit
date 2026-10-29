package kubeconfig

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

// isRoot is false on Windows: an elevated meshctl is common (the built-in
// Administrator is always elevated), so ownedByUser guards instead.
func isRoot() bool { return false }

// ownedByUser refuses a path that is not this user's: its owner must be
// the token's user, or Administrators (what an elevated process creates)
// inside this user's own profile. An elevated meshctl given another
// user's KUBECONFIG is refused, as root is on Unix (TD-CLI-87). The owner
// and the location come from one handle opened through every junction
// and link, so a junction cannot pass another place off as the profile
// (review TD-CLI-87 H1).
func ownedByUser(path string) error {
	handle, err := openForQuery(path)
	if err != nil {
		// A missing file wraps fs.ErrNotExist (syscall.Errno.Is).
		return fmt.Errorf("kubeconfig: opening %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	owner, err := handleOwner(handle)
	if err != nil {
		return fmt.Errorf("kubeconfig: reading the owner of %s: %w", path, err)
	}
	token, err := currentToken()
	if err != nil {
		return fmt.Errorf("kubeconfig: reading this user: %w", err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("kubeconfig: reading this user: %w", err)
	}
	if owner.Equals(user.User.Sid) {
		return nil
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("%w: %s belongs to %s", ErrUnsafe, path, owner.String())
	}
	// Only the open may report a missing file: a path that cannot be
	// resolved is refused, never skipped (re-review L1).
	final, err := finalPath(handle)
	if err != nil {
		return fmt.Errorf("%w: resolving %s: %s", ErrUnsafe, path, err.Error())
	}
	profile, err := profileDir(token)
	if err != nil {
		return fmt.Errorf("%w: reading this user's profile: %s", ErrUnsafe, err.Error())
	}
	if !within(final, profile) {
		return fmt.Errorf("%w: %s (%s) belongs to Administrators outside this user's profile", ErrUnsafe, path, final)
	}
	return nil
}

// currentToken is a real handle to this process's token: the profile
// lookup is documented for one, not for the pseudo-handle.
func currentToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	return token, err
}

// openForQuery opens a file or directory to read its security, following
// reparse points to the object itself.
func openForQuery(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func handleOwner(handle windows.Handle) (*windows.SID, error) {
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	if descriptor == nil {
		return nil, errors.New("no security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, errors.New("no owner (a volume without security)")
	}
	return owner, nil
}

// finalPath is where handle's object really is, as a DOS path.
func finalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		// FILE_NAME_NORMALIZED | VOLUME_NAME_DOS: both 0. The buffer holds
		// at most what the call asked for, a uint32.
		size, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0) //nolint:gosec // G115
		if err != nil {
			return "", err
		}
		if int(size) < len(buffer) {
			path := windows.UTF16ToString(buffer[:size])
			if rest, ok := strings.CutPrefix(path, `\\?\UNC\`); ok {
				return `\\` + rest, nil
			}
			return strings.TrimPrefix(path, `\\?\`), nil
		}
		buffer = make([]uint16, size)
	}
}

// profileDir is the token user's profile, resolved as finalPath resolves.
func profileDir(token windows.Token) (string, error) {
	profile, err := token.GetUserProfileDirectory()
	if err != nil {
		return "", err
	}
	handle, err := openForQuery(profile)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	return finalPath(handle)
}

// within reports whether path is dir or below it. Case is compared as
// NTFS compares it, rune by rune in upper case, not by Unicode folding
// (which takes the Kelvin sign for k).
func within(path, dir string) bool {
	path, dir = strings.ReplaceAll(path, "/", `\`), strings.TrimRight(strings.ReplaceAll(dir, "/", `\`), `\`)
	path = strings.TrimRight(path, `\`)
	if !hasPrefixUpper(path, dir) {
		return false
	}
	return len(path) == len(dir) || path[len(dir)] == '\\'
}

// hasPrefixUpper reports whether text starts with prefix, rune by rune in
// upper case; a match covers exactly len(prefix) bytes of text.
func hasPrefixUpper(text, prefix string) bool {
	for prefix != "" {
		if text == "" {
			return false
		}
		want, wantSize := utf8.DecodeRuneInString(prefix)
		got, gotSize := utf8.DecodeRuneInString(text)
		if wantSize != gotSize || unicode.ToUpper(want) != unicode.ToUpper(got) {
			return false
		}
		prefix, text = prefix[wantSize:], text[gotSize:]
	}
	return true
}

func retryableRename(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
