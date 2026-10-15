package main

import (
	"context"
	"fmt"
	"io"

	"meshtransit.net/core/internal/platform/config"
)

const usage = "Usage: meshcore [serve | version | config validate | identity fingerprint | migrate status | migrate up | bootstrap check | bootstrap apply | account revoke-sessions|quarantine|release <principal-id>]\n"

func execute(
	ctx context.Context,
	args []string,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
) int {
	switch {
	case len(args) == 0:
		return run(ctx, lookup, errorOutput)
	case len(args) == 1 && args[0] == "serve":
		return run(ctx, lookup, errorOutput)
	case len(args) == 1 && args[0] == "version":
		return runVersion(output, errorOutput)
	case len(args) == 2 && args[0] == "config" && args[1] == "validate":
		return runConfigValidate(ctx, lookup, output, errorOutput)
	case len(args) == 2 && args[0] == "identity" && args[1] == "fingerprint":
		return runIdentityFingerprint(ctx, lookup, output, errorOutput)
	case len(args) == 2 && args[0] == "migrate" && (args[1] == "status" || args[1] == "up"):
		return runMigrate(ctx, args[1], lookup, output, errorOutput, openMigrationService)
	case len(args) == 2 && args[0] == "bootstrap" && (args[1] == "check" || args[1] == "apply"):
		return runBootstrap(ctx, args[1], lookup, output, errorOutput)
	case len(args) == 3 && args[0] == "account" && accountCommandActions[args[1]] != "":
		return runAccount(ctx, args[1], args[2], lookup, output, errorOutput)
	case len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help"):
		if _, err := io.WriteString(output, usage); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "meshcore: write help output failed")
			return 1
		}
		return 0
	default:
		if _, err := io.WriteString(errorOutput, usage); err != nil {
			return 1
		}
		return 2
	}
}
