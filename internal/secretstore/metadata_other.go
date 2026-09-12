//go:build !linux

package secretstore

import (
	"fmt"
	"os"
)

func validateSystemdCredentialMetadata(os.FileInfo) error {
	return fmt.Errorf("%w: systemd credentials are unsupported on this platform", ErrKeyInvalid)
}
