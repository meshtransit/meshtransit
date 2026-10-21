package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
)

// hostRouteArgs maps the commands that change the host's route settings to
// the routes command they are: meshctl routes ARGS..., exit use POOL and
// exit serve on|off. handled is false for everything else, exit approve
// and exit status included, which need the daemon.
func hostRouteArgs(args []string) (routes []string, handled bool) {
	switch {
	case args[0] == "routes":
		return args[1:], true
	case args[0] != "exit" || len(args) < 2:
		return nil, false
	case args[1] == "use":
		if len(args) != 3 {
			return nil, true
		}
		return []string{"exit-use", args[2]}, true
	case args[1] == "serve":
		if len(args) != 3 || (args[2] != "on" && args[2] != "off") {
			return nil, true
		}
		return []string{"exit-mode", args[2]}, true
	}
	return nil, false
}

// runHostRoutes runs one routes command through Routes; routes is empty
// for a malformed command, answered with the usage of what was typed.
func runHostRoutes(command string, routes []string, stdout, stderr io.Writer,
	run func([]string, io.Writer, io.Writer) int,
) int {
	if len(routes) == 0 {
		usage := exitUsage
		if command == "routes" {
			usage = routesUsage
		}
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	if run == nil {
		_, _ = fmt.Fprintln(stderr, "meshctl: this build cannot change the host's route settings")
		return 1
	}
	return run(routes, stdout, stderr)
}

const routesUsage = `usage: meshctl routes COMMAND, as meshnetd routes (Windows: meshd routes):
       show, accept on|off, router-mode on|off, advertise PREFIX..., exit-use POOL|auto|off, ...
       A change needs root, which meshctl asks sudo for (Windows: an administrator terminal).`

const exitUsage = `usage: meshctl exit use POOL|auto|off   send this machine's Internet traffic through an Exit Pool
       meshctl exit serve on|off        offer to be an exit node
       meshctl exit status              this machine's choice and the exit node in use
       meshctl exit approve ID...       use exit nodes added since the pool was pinned`

// runExitStatus prints the host's exit settings and the exit node the
// daemon uses. Settings that cannot be read (Windows: not an administrator)
// are skipped with the reason; a daemon that cannot answer fails it.
func runExitStatus(ctx context.Context, stdout, stderr io.Writer, client DaemonClient,
	routes func([]string, io.Writer, io.Writer) int,
) int {
	if routes != nil {
		var settings bytes.Buffer
		if code := routes([]string{"show"}, &settings, stderr); code != 0 {
			settings.Reset()
		}
		lines := bufio.NewScanner(&settings)
		for lines.Scan() {
			if strings.HasPrefix(lines.Text(), "exit-") {
				_, _ = fmt.Fprintln(stdout, lines.Text())
			}
		}
	}
	status, err := client.Status(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	_, _ = fmt.Fprintf(stdout, "Exit: %s\n", formatExitStatus(status.Exit))
	return 0
}

// runExit runs meshctl exit approve ID...: the pool in use may carry
// traffic through the exit nodes named, which Core added to it since this
// machine pinned it, or the pool named takes the name the settings use.
// Which pool to use is root's choice (meshctl exit use).
func runExit(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) < 2 || len(args) > 17 || args[0] != "approve" {
		_, _ = fmt.Fprintln(stderr, exitUsage)
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
