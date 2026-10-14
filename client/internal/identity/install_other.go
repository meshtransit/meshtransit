//go:build !android

package identity

import (
	"fmt"
	"os"
)

// installNew makes temporary the record final, failing with an error that
// matches os.ErrExist when final already exists. A hard link is atomic and
// never replaces; temporary is then removed.
func installNew(root *os.Root, temporary, final string) error {
	if err := root.Link(temporary, final); err != nil {
		return err
	}
	if err := root.Remove(temporary); err != nil {
		return fmt.Errorf("removing linked temporary identity record: %w", err)
	}
	return nil
}
