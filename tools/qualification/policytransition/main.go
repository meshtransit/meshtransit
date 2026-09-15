// Command policytransition publishes a bounded policy transition on a disposable Network.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr, executeTransition)
	stop()
	os.Exit(exitCode)
}
