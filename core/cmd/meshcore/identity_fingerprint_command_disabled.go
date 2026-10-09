//go:build !dexbroker

package main

import (
	"context"
	"io"

	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

func runIdentityFingerprint(
	context.Context,
	config.LookupFunc,
	io.Writer,
	io.Writer,
) int {
	return 1
}
