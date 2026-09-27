//go:build linux || darwin

package relayfile

import (
	"os"
	"syscall"
)

func openDirectoryFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
