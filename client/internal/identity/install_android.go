package identity

import "os"

// installNew makes temporary the record final, failing with an error that
// matches os.ErrExist when final already exists. Android's SELinux policy
// forbids apps hard links in their data directory, so the record is renamed
// in place without replacing (renameNoReplace).
func installNew(root *os.Root, temporary, final string) error {
	return renameNoReplace(root, temporary, final)
}
