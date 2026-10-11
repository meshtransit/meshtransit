//go:build !linux && !darwin

package peercred

func uidOf(int) (uint32, error) { return 0, ErrUnavailable }
