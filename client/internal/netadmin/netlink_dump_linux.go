package netadmin

import (
	"errors"

	"github.com/vishvananda/netlink"
)

// dumpAttempts bounds how often a netlink dump is read again after the
// kernel's tables changed during it, as they do on hosts with containers.
const dumpAttempts = 3

// dumped runs a netlink dump again while the kernel reports it interrupted
// (netlink.ErrDumpInterrupted), whose results may be inconsistent; after
// dumpAttempts it returns that error.
func dumped[T any](dump func() (T, error)) (T, error) {
	var result T
	var err error
	for range dumpAttempts {
		if result, err = dump(); !errors.Is(err, netlink.ErrDumpInterrupted) {
			return result, err
		}
	}
	return result, err
}
