//go:build !linux

package dataplane

import "errors"

func newWireGuardFactory() (wireGuardFactory, error) {
	return nil, errors.New("dataplane: wireguard poc is supported only on linux")
}
