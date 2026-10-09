// Command dexcompile verifies the compile-time Dex adapter contract.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := run(ctx, os.Args[1:], os.Stdout, os.Stderr, verifyCompileContract)
	stop()
	os.Exit(exitCode)
}
