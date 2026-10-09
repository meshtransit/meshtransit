// Command meshrelay runs MeshTransit Interchange, the relay that forwards
// encrypted node traffic when no direct path exists (docs/protocol/mtrp-v1.md).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Build metadata, set by the release pipeline with -ldflags -X.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, env func(string) (string, bool), stdout, stderr io.Writer) int {
	command := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		command, args = args[0], args[1:]
	}
	switch command {
	case "serve":
		cfg, err := parseServeConfig(args, env, stderr)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "meshrelay: %v\n", err)
			return 2
		}
		if err := serve(ctx, cfg, stderr); err != nil {
			_, _ = fmt.Fprintf(stderr, "meshrelay: %v\n", err)
			return 1
		}
		return 0
	case "genkey":
		if err := genkey(args, stdout, stderr); err != nil {
			_, _ = fmt.Fprintf(stderr, "meshrelay: %v\n", err)
			return 1
		}
		return 0
	case "version":
		_, _ = fmt.Fprintf(stdout, "meshrelay %s (%s)\n", version, commit)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "meshrelay: unknown command %q (serve, genkey, version)\n", command)
		return 2
	}
}
