//go:build linux || darwin

package config

import (
	"os"
	"syscall"
)

func openPrivateIdentityKey(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
