//go:build !unix

package selfhost

import (
	"errors"
	"fmt"
)

func readRegularFile(string, int64) ([]byte, error) {
	return nil, fmt.Errorf("%w: self-host setup runs on Linux", ErrSecrets)
}

// LockSetup is unavailable: self-host setup runs on Linux.
func LockSetup(string) (func(), error) {
	return nil, fmt.Errorf("%w: self-host setup runs on Linux", ErrSecrets)
}

// ErrSetupLocked reports that another setup run holds the lock.
var ErrSetupLocked = errors.New("another setup run holds the lock")
