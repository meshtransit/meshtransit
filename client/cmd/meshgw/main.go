// Command meshgw runs one replica of the MeshTransit Kubernetes gateway: a
// userspace mesh node in an unprivileged pod (k8s-gateway-plan §4.4).
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"meshtransit.net/client/internal/meshgw"
)

func main() {
	os.Exit(run())
}

func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	cfg, err := meshgw.LoadConfig(os.Getenv)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		return 2
	}
	if err := meshgw.Run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("gateway stopped", "error", err)
		return 1
	}
	return 0
}
