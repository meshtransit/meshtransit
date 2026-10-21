package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/cli"
	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/routesettings"
)

// changeCaptiveWindow opens or closes the captive portal window, with the
// privileges it needs already held: it writes the window file the helper
// (the service on Windows) reads (exit node design §17.4).
func changeCaptiveWindow(request cli.CaptiveRequest, stdout, stderr io.Writer) int {
	path := config.DefaultCaptiveWindowPath
	if request.Close {
		if err := captive.CloseWindow(path); err != nil {
			_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, "Captive portal window closed.")
		return 0
	}
	settings, err := routesettings.Load(config.DefaultRouteSettingsPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
	}
	switch {
	case settings.ExitCaptiveOff:
		_, _ = fmt.Fprintln(stderr, "meshctl: captive portal windows are off on this machine "+
			"(meshctl routes exit-captive on allows them)")
		return 1
	case settings.ExitUse == "" && !settings.ExitAllowManaged:
		_, _ = fmt.Fprintln(stderr, "meshctl: this machine uses no exit node; it reaches a captive portal without a window")
		return 1
	}
	window, err := captive.OpenWindow(path, request.For, time.Now())
	if errors.Is(err, fs.ErrNotExist) {
		// No runtime directory: the helper never ran to read the window.
		_, _ = fmt.Fprintln(stderr, "meshctl: the MeshTransit helper is not running on this machine")
		return 1
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshctl: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Captive portal window open for %s: until then HTTP and HTTPS of every program on "+
		"this machine go straight to the network, not through the exit node.\n"+
		"Sign in to the portal in a browser; the window closes by itself, or with meshctl exit captive --close.\n",
		window.Duration())
	return 0
}
