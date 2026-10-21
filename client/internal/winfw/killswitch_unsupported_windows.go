//go:build windows && !amd64 && !arm64

package winfw

import "errors"

var errUnsupported = errors.New("winfw: the exit kill switch needs 64-bit Windows")

// Enable fails: the filter layouts are those of 64-bit Windows.
func Enable(Config) error { return errUnsupported }

// Disable has nothing to remove.
func Disable() error { return nil }

// Installed reports none.
func Installed() (bool, error) { return false, nil }

// HoldCaptive fails: no kill switch to open a window in.
func HoldCaptive([]Rule) (func(), error) { return nil, errUnsupported }
