package peercred

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// xucredVersion is XUCRED_VERSION from <sys/ucred.h>.
const xucredVersion = 0

// uidOf reads LOCAL_PEERCRED: the credentials the peer had when it connected.
func uidOf(fd int) (uint32, error) {
	credentials, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("peercred: reading peer credentials: %w", err)
	}
	if credentials == nil || credentials.Version != xucredVersion {
		return 0, errors.New("peercred: kernel returned no peer credentials")
	}
	return credentials.Uid, nil
}
