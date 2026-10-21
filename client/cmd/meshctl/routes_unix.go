//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"meshtransit.net/client/internal/cli"
	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/routesettings/routescli"
)

// hostRoutes shows and changes the host's route settings as meshnetd routes
// does, in the default file only. Anyone reads them; a change needs root,
// so meshctl runs the same command again through sudo, which asks for the
// password.
func hostRoutes(args []string, quiet bool, stdout, stderr io.Writer) (int, bool) {
	delegated := false
	command := routescli.Command{
		Program: "meshctl", Privilege: "root privileges", FixedPath: config.DefaultRouteSettingsPath, Quiet: quiet,
		Privileged: func() bool { return os.Geteuid() == 0 },
		Elevate: func() int {
			delegated = true
			return runWithSudo(stderr, "changing route settings")
		},
	}
	code := command.Run(args, stdout, stderr)
	return code, delegated
}

// elevatedMarker is set in the environment of the meshctl sudo runs: one
// that is still not root then (sudo set to run as another user, a shim)
// stops instead of asking sudo again and again.
const elevatedMarker = "MESHCTL_SUDO_RUN"

// runWithSudo runs this meshctl invocation again as root and returns its
// exit code; what names the change, for the messages.
func runWithSudo(stderr io.Writer, what string) int {
	if os.Getenv(elevatedMarker) != "" {
		_, _ = fmt.Fprintln(stderr, "meshctl: sudo did not make meshctl root: run it as root")
		return 1
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: root privileges are required for %s: run it as root\n", what)
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: finding meshctl to run it with sudo: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "meshctl: %s needs root; asking sudo\n", what)
	// The user's own command, run again by the same binary.
	// Interrupting meshctl interrupts sudo through the terminal: no deadline.
	// sudo resets the environment: carry the marker and the socket meshctl
	// was told to use.
	command := []string{"-u", "root", "--", "env", elevatedMarker + "=1"}
	if socket := os.Getenv("MESHCTL_SOCKET"); socket != "" {
		command = append(command, "MESHCTL_SOCKET="+socket)
	}
	command = append(append(command, executable), os.Args[1:]...)
	sudoCommand := exec.CommandContext(context.Background(), sudo, command...) //nolint:gosec // see above
	sudoCommand.Stdin, sudoCommand.Stdout, sudoCommand.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = sudoCommand.Run()
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		// A signal leaves no code (-1): report a failure, not 255.
		return max(exited.ExitCode(), 1)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: running sudo: %v\n", err)
		return 1
	}
	return 0
}

// hostCaptive opens or closes the captive portal window as root, running
// meshctl again through sudo when not root.
func hostCaptive(request cli.CaptiveRequest, stdout, stderr io.Writer) (int, bool) {
	if os.Geteuid() != 0 {
		return runWithSudo(stderr, "a captive portal window"), true
	}
	return changeCaptiveWindow(request, stdout, stderr), false
}
