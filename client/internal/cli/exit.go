package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// runExit runs meshctl exit approve ID...: the pool in use may carry
// traffic through the exit nodes named, which Core added to it since this
// machine pinned it, or the pool named takes the name the settings use.
// Which pool to use is root's choice (meshnetd routes exit-use).
func runExit(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) < 2 || len(args) > 17 || args[0] != "approve" {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl exit approve ID... (the exit nodes or pool meshctl status lists)")
		return 2
	}
	result, err := client.ApproveExitNodes(ctx, args[1:])
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	_, _ = fmt.Fprintf(stdout, "Approved in pool %s: %s.\n", result.Pool, strings.Join(result.Approved, ", "))
	return 0
}
