package kubecafile

import (
	"errors"

	"golang.org/x/sys/windows"
)

// retryableRename reports a target another process holds open.
func retryableRename(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
