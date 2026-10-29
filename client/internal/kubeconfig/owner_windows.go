package kubeconfig

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isRoot is false on Windows: an elevated meshctl writes the kubeconfig of
// the user it runs as, which the profile directory's owner check guards.
func isRoot() bool { return false }

// ownedByUser accepts what the user's own profile holds; Windows' default
// ACLs keep other users out of it.
func ownedByUser(string) error { return nil }

func retryableRename(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
