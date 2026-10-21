//go:build windows

package main

import (
	"fmt"
	"io"

	"golang.org/x/sys/windows"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/routesettings/routescli"
)

// administratorHint says how to get an administrator's full token.
const administratorHint = "meshctl: administrator rights are required for route settings: " +
	"open Terminal or PowerShell with \"Run as administrator\" and run the same meshctl command"

// hostRoutes shows and changes the host's route settings as meshd routes
// does, in the default file only. Only SYSTEM and Administrators may open
// that file (privatefile), so reading needs an administrator's full token
// as a change does, which only a terminal opened as administrator has.
func hostRoutes(args []string, quiet bool, stdout, stderr io.Writer) (int, bool) {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	if !elevated {
		_, _ = fmt.Fprintln(stderr, administratorHint)
		return 1, false
	}
	command := routescli.Command{
		Program: "meshctl", Privilege: "administrator rights", FixedPath: config.DefaultRouteSettingsPath,
		Quiet: quiet, Privileged: func() bool { return elevated },
	}
	return command.Run(args, stdout, stderr), false
}
