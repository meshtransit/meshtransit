//go:build !dexbroker

package main

import (
	"context"
	"io"

	"meshtransit.net/core/internal/platform/config"
)

func runIdentityFingerprint(
	context.Context,
	config.LookupFunc,
	io.Writer,
	io.Writer,
) int {
	return 1
}

// identityFingerprintFromSettings needs the dexbroker build, where meshcore
// setup runs.
func identityFingerprintFromSettings(map[string]string) (string, error) {
	return "", errIdentityBrokerUnavailable
}
