// Command enrollmentcredential issues one short-lived single-use credential on a disposable Network.
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
	exitCode := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr, rand.Reader, executeIssue)
	stop()
	os.Exit(exitCode)
}
