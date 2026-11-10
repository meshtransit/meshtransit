package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"meshtransit.net/client/internal/cli/localapi"
)

func runDown(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: meshctl down")

		return 2
	}
	result, err := client.Down(ctx)
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if result.State != "down" {
		return writeRuntimeError(stderr, fmt.Errorf("daemon returned unsupported connection state %q", result.State))
	}
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	if result.Changed {
		_, _ = fmt.Fprintln(stdout, "Disconnected. This machine stays off the network until meshctl up.")
	} else {
		_, _ = fmt.Fprintln(stdout, "Already disconnected. Run meshctl up to connect again.")
	}

	return 0
}

func runLogout(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	isJSON bool,
	client DaemonClient,
) int {
	remove := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--remove":
		remove = true
	default:
		_, _ = fmt.Fprintln(stderr, "usage: meshctl logout [--remove]")

		return 2
	}
	call := client.SignOut
	if remove {
		call = client.Logout
	}
	result, err := call(ctx)
	var apiErr *localapi.APIError
	if !remove && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		// An older meshd has no sign-out: it only removes.
		_, _ = fmt.Fprintln(stderr, "meshctl: meshd is older than meshctl and cannot sign out; "+
			"update meshd, or run meshctl logout --remove to remove this machine")

		return 1
	}
	if err != nil {
		return writeRuntimeError(stderr, err)
	}
	if result.State != "logged_out" && result.State != "not_registered" && result.State != "signed_out" {
		return writeRuntimeError(stderr, fmt.Errorf("daemon returned unsupported logout state %q", result.State))
	}
	if isJSON {
		return writeJSON(stdout, stderr, result)
	}
	switch {
	case result.State == "not_registered":
		_, _ = fmt.Fprintln(stdout, "This machine is not registered; nothing to log out.")
	case result.State == "signed_out":
		_, _ = fmt.Fprintln(stdout, "Signed out. This machine keeps its device, address and name in the Network.")
		_, _ = fmt.Fprintln(stdout, "Run meshctl login to sign back in. Giving the machine away? Run meshctl logout --remove.")
	case result.AlreadyRemoved:
		_, _ = fmt.Fprintln(stdout, "This machine was already removed from its Network; its local keys were reset.")
		_, _ = fmt.Fprintln(stdout, "Run meshctl up to enroll it again.")
	default:
		_, _ = fmt.Fprintln(stdout, "Logged out: this machine was removed from its Network.")
		_, _ = fmt.Fprintln(stdout, "Run meshctl up to enroll it again.")
	}

	return 0
}
