//go:build !linux && !darwin

package config

import "os"

func openPrivateIdentityKey(_ *os.Root, _ string) (*os.File, error) {
	return nil, ErrInvalid
}
