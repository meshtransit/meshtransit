// Command meshgw runs one replica of the MeshTransit Kubernetes gateway: a
// userspace mesh node in an unprivileged pod (k8s-gateway-plan §4.4).
// `meshgw check [--preflight]` is its install's test and preflight (K1c).
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"meshtransit.net/client/internal/kubecheck"
	"meshtransit.net/client/internal/kubetoken"
	"meshtransit.net/client/internal/meshgw"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "check" {
		return kubecheck.Main(ctx, os.Args[2:], os.Getenv, os.Stdout, os.Stderr, kubetoken.ReadAudiences)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
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
