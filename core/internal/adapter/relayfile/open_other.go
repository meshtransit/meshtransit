//go:build !linux && !darwin

package relayfile

import "os"

func openDirectoryFile(_ *os.Root, _ string) (*os.File, error) {
	return nil, ErrInvalid
}
