//go:build !windows

package dnsconfig

import (
	"errors"
	"syscall"
)

// addressTaken reports a listen refused because another socket holds the
// address: without SO_REUSEPORT none binds it while meshd holds it.
func addressTaken(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
