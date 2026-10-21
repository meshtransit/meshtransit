//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/routesettings/routescli"
)

// hostRoutes shows and changes the host's route settings as meshnetd routes
// does, in the default file only. Anyone reads them; a change needs root,
// so meshctl runs the same command again through sudo, which asks for the
// password.
func hostRoutes(args []string, stdout, stderr io.Writer) int {
	command := routescli.Command{
		Program: "meshctl", Privilege: "root privileges", FixedPath: config.DefaultRouteSettingsPath,
		Privileged: func() bool { return os.Geteuid() == 0 },
		Elevate:    func() int { return runWithSudo(stderr) },
	}
	return command.Run(args, stdout, stderr)
}

// elevatedMarker is set in the environment of the meshctl sudo runs: one
// that is still not root then (sudo set to run as another user, a shim)
// stops instead of asking sudo again and again.
const elevatedMarker = "MESHCTL_SUDO_RUN"

// runWithSudo runs this meshctl invocation again as root and returns its
// exit code.
func runWithSudo(stderr io.Writer) int {
	if os.Getenv(elevatedMarker) != "" {
		_, _ = fmt.Fprintln(stderr, "meshctl: sudo did not make meshctl root: run it as root")
		return 1
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "meshctl: root privileges are required to change route settings: run it as root")
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: finding meshctl to run it with sudo: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stderr, "meshctl: changing route settings needs root; asking sudo")
	// The user's own command, run again by the same binary.
	// Interrupting meshctl interrupts sudo through the terminal: no deadline.
	sudoCommand := exec.CommandContext(context.Background(), sudo, //nolint:gosec // see above
		append([]string{"-u", "root", "--", "env", elevatedMarker + "=1", executable}, os.Args[1:]...)...)
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
