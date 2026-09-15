// Command managementsession creates one short-lived synthetic management session on a pristine qualification deployment.
package main

import (
	"context"
	"crypto/rand"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr, rand.Reader, executeSeed)
	stop()
	os.Exit(exitCode)
}
