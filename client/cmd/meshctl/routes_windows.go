//go:build windows

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/windows"

	"meshtransit.net/client/internal/cli"
	"meshtransit.net/client/internal/cli/localapi"
	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/routesettings/routescli"
)

// administratorHint says how to get an administrator's full token.
const administratorHint = "meshctl: administrator rights are required for route settings: " +
	"open Terminal or PowerShell with \"Run as administrator\" and run the same meshctl command"

// routeChoicesTimeout bounds one call to meshd for the route choices.
const routeChoicesTimeout = 10 * time.Second

// hostRoutes shows and changes the host's route settings as meshd routes
// does, in the default file only. Only SYSTEM and Administrators may open
// that file (privatefile), so the whole settings need an administrator's
// full token, which only a terminal opened as administrator has. Without
// it, the operators group reads and changes the host's own choices
// (exit-use, accept, exit-allow-lan) through meshd, while root lets them.
func hostRoutes(args []string, quiet bool, stdout, stderr io.Writer) (int, bool) {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	if !elevated {
		if change, show, ok := routeChoiceCommand(args); ok {
			return routeChoicesThroughMeshd(change, show, quiet, stdout, stderr), false
		}
		_, _ = fmt.Fprintln(stderr, administratorHint)
		return 1, false
	}
	command := routescli.Command{
		Program: "meshctl", Privilege: "administrator rights", FixedPath: config.DefaultRouteSettingsPath,
		Quiet: quiet, Privileged: func() bool { return elevated },
	}
	return command.Run(args, stdout, stderr), false
}

// routeChoicesThroughMeshd reads or changes the choices through meshd's
// /v1/route-choices and prints them.
func routeChoicesThroughMeshd(change localapi.RouteChoiceChange, show, quiet bool, stdout, stderr io.Writer) int {
	client, err := localapi.New(config.DefaultSocketPath, routeChoicesTimeout)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), routeChoicesTimeout)
	defer cancel()
	var choices localapi.RouteChoices
	if show {
		choices, err = client.RouteChoices(ctx)
	} else {
		choices, err = client.ChangeRouteChoices(ctx, change)
	}
	if err != nil {
		var refused *localapi.APIError
		switch {
		case errors.As(err, &refused) && refused.Code == "operators_off":
			_, _ = fmt.Fprintln(stderr, "meshctl: an administrator keeps these route settings "+
				"(meshctl routes operators on, run as administrator, lets the MeshTransit Users group change them)")
		case errors.Is(err, localapi.ErrEndpointMissing), errors.As(err, &refused) && refused.Code == "forbidden":
			// An older meshd, or a user outside MeshTransit Users.
			_, _ = fmt.Fprintln(stderr, administratorHint)
		default:
			_, _ = fmt.Fprintf(stderr, "meshctl: %v (or run meshctl in a terminal opened as administrator)\n", err)
		}
		return 1
	}
	if quiet && !show {
		return 0
	}
	onOff := map[bool]string{true: "on", false: "off"}
	if _, err := fmt.Fprintf(stdout, "accept: %s\nexit-use: %s\nexit-allow-lan: %s\noperators: %s\n",
		onOff[choices.AcceptRoutes], cmp.Or(choices.ExitUse, "off"), onOff[choices.ExitAllowLAN],
		onOff[choices.Operators]); err != nil {
		return 1
	}
	if show {
		_, _ = fmt.Fprintln(stderr, "meshctl: the other route settings need a terminal opened as administrator")
	}
	return 0
}

// hostCaptive opens or closes the captive portal window from a terminal
// opened as administrator.
func hostCaptive(request cli.CaptiveRequest, stdout, stderr io.Writer) (int, bool) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		_, _ = fmt.Fprintln(stderr, "meshctl: administrator rights are required for a captive portal window: "+
			"open Terminal or PowerShell with \"Run as administrator\" and run the same meshctl command")
		return 1, false
	}
	return changeCaptiveWindow(request, stdout, stderr), false
}
