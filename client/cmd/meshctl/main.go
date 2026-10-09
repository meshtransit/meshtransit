// Command meshctl controls the local MeshTransit daemon.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"meshtransit.net/client/internal/cli"
	"meshtransit.net/client/internal/cli/localapi"
	"meshtransit.net/client/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return cli.Run(
		ctx,
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		cli.Options{
			Build:  version.Current(),
			Getenv: os.Getenv,
			Stdin:  os.Stdin,
			NewClient: func(socketPath string, timeout time.Duration) (cli.DaemonClient, error) {
				return localapi.New(socketPath, timeout)
			},
		},
	)
}
