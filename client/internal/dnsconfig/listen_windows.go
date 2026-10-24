package dnsconfig

import (
	"errors"

	"golang.org/x/sys/windows"
)

// The resolver's sockets take no SO_EXCLUSIVEADDRUSE. meshd runs as SYSTEM,
// and Windows lets no socket of another account bind the resolver's address
// over it (SO_REUSEADDR included); the option would add little and keep the
// TCP port from binding again for a while after a restart, and keep other
// programs off 0.0.0.0:53 (TD-SEC-25).

// addressTaken reports a listen refused because another socket holds the
// address, or the system keeps it from meshd (WSAEACCES: an excluded port
// range, a filter driver).
func addressTaken(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
