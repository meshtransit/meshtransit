// Command dexartifact verifies one pinned patched Dex artifact and its evidence.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := run(ctx, os.Args[1:], os.Stdout, os.Stderr, verifyArtifact)
	stop()
	os.Exit(exitCode)
}
