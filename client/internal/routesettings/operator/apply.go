//go:build linux || darwin

package operator

import (
	"errors"
	"fmt"

	"meshtransit.net/client/internal/routesettings"
)

// errUnknownCommand reports a command the protocol does not have.
var errUnknownCommand = errors.New("operator: unknown command")

// changeOf returns the choice request changes.
func changeOf(request Request) (routesettings.ChoiceChange, error) {
	on := request.On
	switch request.Command {
	case CommandExitUse:
		use := request.ExitUse
		return routesettings.ChoiceChange{ExitUse: &use}, nil
	case CommandAccept:
		return routesettings.ChoiceChange{AcceptRoutes: &on}, nil
	case CommandExitAllowLAN:
		return routesettings.ChoiceChange{ExitAllowLAN: &on}, nil
	default:
		return routesettings.ChoiceChange{}, fmt.Errorf("%w: %q", errUnknownCommand, request.Command)
	}
}

// apply returns settings with the request's change, valid and canonical
// (routesettings.ApplyChoices).
func apply(settings routesettings.Settings, request Request) (routesettings.Settings, error) {
	change, err := changeOf(request)
	if err != nil {
		return settings, err
	}
	return routesettings.ApplyChoices(settings, change)
}

// choicesOf returns the part of settings an operator sees.
func choicesOf(settings routesettings.Settings) Choices {
	choices := settings.Choices()
	return Choices{
		AcceptRoutes: choices.AcceptRoutes,
		ExitUse:      choices.ExitUse,
		ExitAllowLAN: choices.ExitAllowLAN,
		Operators:    choices.Operators,
	}
}
