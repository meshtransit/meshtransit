package peercred

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func uidOf(fd int) (uint32, error) {
	credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("peercred: reading peer credentials: %w", err)
	}
	if credentials == nil {
		return 0, errors.New("peercred: kernel returned no peer credentials")
	}
	return credentials.Uid, nil
}
