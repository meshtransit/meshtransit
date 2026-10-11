//go:build !linux && !darwin

package dataplane

import "errors"

func newWireGuardFactory() (wireGuardFactory, error) {
	return nil, errors.New("dataplane: encrypted packet path is supported only on linux")
}
