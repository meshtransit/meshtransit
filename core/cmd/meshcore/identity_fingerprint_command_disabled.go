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
