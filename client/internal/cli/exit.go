package cli

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/cli/localapi"
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
func runHostRoutes(command string, routes []string, quiet bool, stdout, stderr io.Writer,
	run func([]string, bool, io.Writer, io.Writer) (int, bool),
) (int, bool) {
	if len(routes) == 0 {
		usage := exitUsage
		if command == "routes" {
			usage = routesUsage
		}
		_, _ = fmt.Fprintln(stderr, usage)
		return 2, false
	}
	if run == nil {
		_, _ = fmt.Fprintln(stderr, "meshctl: this build cannot change the host's route settings")
		return 1, false
	}
	return run(routes, quiet, stdout, stderr)
}

var exitServeText = map[string]string{
	"on":  "offered; Core makes this machine an exit node of the pool it is added to",
	"off": "not offered; this machine forwards no one's Internet traffic",
}

// Waiting for meshd to take an exit choice.
const (
	exitWaitDefault  = 15 * time.Second
	exitWaitInterval = 500 * time.Millisecond
)

// waitForExit asks meshd, until it applied the exit choice use (a pool,
// auto or off) or ExitWait ran out, and prints one line on where the
// Internet goes. The choice is saved whatever meshd says.
func waitForExit(ctx context.Context, use string, stdout io.Writer, options Options, global globalOptions) int {
	client, err := options.NewClient(global.socketPath, global.timeout)
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "Exit: saved; it applies when meshd runs")
		return 0
	}
	wait := cmp.Or(options.ExitWait, exitWaitDefault)
	deadline := time.Now().Add(wait)
	for {
		status, err := client.Status(ctx)
		if ctx.Err() != nil {
			return 1
		}
		if err != nil {
			_, _ = fmt.Fprintln(stdout, "Exit: saved; it applies when meshd runs")
			return 0
		}
		if line, applied := exitApplied(use, status.Exit); applied {
			_, _ = fmt.Fprintln(stdout, line)
			return 0
		}
		if !time.Now().Before(deadline) {
			_, _ = fmt.Fprintln(stdout, "Exit: not applied yet; meshctl exit status shows when it is")
			return 0
		}
		select {
		case <-ctx.Done():
			return 1
		case <-time.After(min(exitWaitInterval, wait/10)):
		}
	}
}

// exitApplied reports the line to print once meshd applied the choice use:
// no exit for off (or the pool the administrator manages, when allowed);
// for a pool or auto, an exit status for that choice (meshd reports Use as
// chosen, "auto" included) that routes, says why it does not, or names a
// pool not granted. auto still measuring its pools has no exit node yet.
// A refusal or error is the helper's answer to this request: meshd clears
// the previous one when it asks anew.
func exitApplied(use string, exit *localapi.ExitStatus) (string, bool) {
	if use == "off" {
		switch {
		case exit == nil:
			return "Exit: off; this machine uses its own network again", true
		case exit.Use == "managed":
			return "Exit: off here; the administrator's pool applies: " + formatExitStatus(exit), true
		}
		return "", false
	}
	if exit == nil || exit.Use != use {
		return "", false
	}
	switch {
	case exit.Refused != "":
		return "Exit: not routed: " + exit.Refused, true
	case exit.Error != "":
		return "Exit: not routed: " + exit.Error, true
	case exit.Pool == "":
		return "Exit: " + formatExitStatus(exit), true
	case exit.Routing && (exit.ExitNode != "" || use != "auto"):
		return "Exit: " + formatExitStatus(exit), true
	}
	return "", false
}

const routesUsage = `usage: meshctl routes COMMAND, as meshnetd routes (Windows: meshd routes):
       show, accept on|off, router-mode on|off, advertise PREFIX..., exit-use POOL|auto|off, ...
       A change needs root, which meshctl asks sudo for (Windows: an administrator terminal).`

const exitUsage = `usage: meshctl exit use POOL|auto|off   send this machine's Internet traffic through an Exit Pool
       meshctl exit serve on|off        offer to be an exit node
       meshctl exit status              this machine's choice and the exit node in use
       meshctl exit approve ID...       use exit nodes added since the pool was pinned (as root)
       meshctl exit captive [--for D]   let HTTP and HTTPS out for D (2m, at most 5m) to sign in to a captive portal
       meshctl exit captive --close     close that window early`

// runExitStatus prints the host's exit settings and the exit node the
// daemon uses. Settings that cannot be read (Windows: not an administrator)
// are skipped with the reason; a daemon that cannot answer fails it.
func runExitStatus(ctx context.Context, stdout, stderr io.Writer, client DaemonClient,
	routes func([]string, bool, io.Writer, io.Writer) (int, bool),
) int {
	if routes != nil {
		var settings bytes.Buffer
		if code, _ := routes([]string{"show"}, false, &settings, stderr); code != 0 {
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
	_, _ = fmt.Fprintf(stdout, "Exit: %s\n", formatExitStatus(status.Exit)+formatCaptive(status.Captive))
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

// CaptiveRequest opens a captive portal window For long, or closes it.
type CaptiveRequest struct {
	Close bool
	For   time.Duration
}

// parseCaptiveArgs reads meshctl exit captive [--for D] [--close].
func parseCaptiveArgs(args []string) (CaptiveRequest, error) {
	flags := flag.NewFlagSet("meshctl exit captive", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := CaptiveRequest{}
	flags.DurationVar(&request.For, "for", captive.DefaultWindow, "how long the window stays open")
	flags.BoolVar(&request.Close, "close", false, "close the window")
	if err := flags.Parse(args); err != nil {
		return CaptiveRequest{}, err
	}
	switch {
	case flags.NArg() != 0:
		return CaptiveRequest{}, errors.New("unexpected arguments")
	case request.Close && request.For != captive.DefaultWindow:
		return CaptiveRequest{}, errors.New("--close takes no --for")
	case !request.Close && (request.For < time.Second || request.For > captive.MaximumWindow):
		return CaptiveRequest{}, fmt.Errorf("--for must be between 1s and %s", captive.MaximumWindow)
	}
	return request, nil
}

// runCaptive opens or closes a captive portal window through Captive, then
// has meshd look at once, so names follow the window without waiting, and
// prints how the exit stands.
func runCaptive(
	ctx context.Context, args []string, stdout, stderr io.Writer, options Options, global globalOptions,
) int {
	request, err := parseCaptiveArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n%s\n", err, exitUsage)
		return 2
	}
	if global.isJSON {
		_, _ = fmt.Fprintln(stderr, "meshctl: exit captive has no JSON output")
		return 2
	}
	if options.Captive == nil {
		_, _ = fmt.Fprintln(stderr, "meshctl: this build cannot open a captive portal window")
		return 1
	}
	if !request.Close && captiveOffByPool(ctx, options, global) {
		_, _ = fmt.Fprintln(stderr, "meshctl: the Exit Pool this machine uses turns captive portal windows off; "+
			"ask your administrator")
		return 1
	}
	code, delegated := options.Captive(request, stdout, stderr)
	if code != 0 || delegated {
		return code
	}
	client, err := options.NewClient(global.socketPath, global.timeout)
	if err != nil {
		return 0 // the helper has the window; meshd follows it when it runs
	}
	if err := client.CheckCaptiveWindow(ctx); err != nil {
		return 0
	}
	wait := cmp.Or(options.ExitWait, captiveWaitDefault)
	deadline := time.Now().Add(wait)
	for {
		status, err := client.Status(ctx)
		if err != nil || ctx.Err() != nil {
			return 0
		}
		open := status.Captive != nil && status.Captive.State == "open"
		if open != request.Close {
			_, _ = fmt.Fprintf(stdout, "Exit: %s\n", formatExitStatus(status.Exit)+formatCaptive(status.Captive))
			return 0
		}
		if !time.Now().Before(deadline) {
			return 0
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(min(exitWaitInterval, wait/10)):
		}
	}
}

// captiveWaitDefault bounds how long meshctl waits for meshd to see a window.
const captiveWaitDefault = 5 * time.Second

// captiveOffByPool reports whether meshd says the pool in use turns captive
// portal windows off, before root is asked for: the helper would refuse the
// window anyway. A meshd that cannot answer says nothing.
func captiveOffByPool(ctx context.Context, options Options, global globalOptions) bool {
	client, err := options.NewClient(global.socketPath, global.timeout)
	if err != nil {
		return false
	}
	status, err := client.Status(ctx)
	return err == nil && status.Exit != nil && status.Exit.CaptiveOff
}
