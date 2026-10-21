package operator

import (
	"errors"
	"fmt"

	"meshtransit.net/client/internal/routesettings"
)

// errUnknownCommand reports a command the protocol does not have.
var errUnknownCommand = errors.New("operator: unknown command")

// exitUseOff is what meshctl routes exit-use takes for no pool; the request
// may say it too, so no pool can be named "off".
const exitUseOff = "off"

// apply returns settings with the request's change, valid and canonical.
// It changes nothing else: what the request cannot name stays as root set it.
func apply(settings routesettings.Settings, request Request) (routesettings.Settings, error) {
	switch request.Command {
	case CommandExitUse:
		settings.ExitUse = request.ExitUse
		if request.ExitUse == exitUseOff {
			settings.ExitUse = ""
		}
	case CommandAccept:
		settings.AcceptRoutes = request.On
	case CommandExitAllowLAN:
		settings.ExitAllowLAN = request.On
	default:
		return settings, fmt.Errorf("%w: %q", errUnknownCommand, request.Command)
	}
	if err := settings.Validate(); err != nil {
		return settings, err
	}
	return settings.Canonical(), nil
}

// blockedByRoot reports a change that would also turn on something only root
// may: accepting Site routes while root left public routes on would install
// public-range routes too, which root never chose for this host.
func blockedByRoot(settings routesettings.Settings, request Request) (ErrorCode, string, bool) {
	if request.Command == CommandAccept && request.On && settings.AcceptPublicRoutes && !settings.AcceptRoutes {
		return CodeRootSetting, "root's accept-public is on: root turns accept on", true
	}
	return "", "", false
}

// choicesOf returns the part of settings an operator sees.
func choicesOf(settings routesettings.Settings) Choices {
	return Choices{
		AcceptRoutes: settings.AcceptRoutes,
		ExitUse:      settings.ExitUse,
		ExitAllowLAN: settings.ExitAllowLAN,
		Operators:    !settings.OperatorsOff,
	}
}
