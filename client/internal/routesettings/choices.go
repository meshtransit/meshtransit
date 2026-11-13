package routesettings

import (
	"errors"
	"fmt"
)

// ExitUseOff is what an operator sends for no Exit Pool; no pool can be
// named "off".
const ExitUseOff = "off"

// ErrRootSetting reports a choice that would also turn on one of root's
// settings, which root must make.
var ErrRootSetting = errors.New("routesettings: the change needs one of root's settings")

// Choices are the host's own route choices (exit node design §11): which
// Exit Pool its Internet traffic uses, whether it installs the private Site
// routes Core grants, and whether its attached private subnets stay off the
// exit node. Operators reads whether the operators may change them.
type Choices struct {
	AcceptRoutes bool
	ExitUse      string
	ExitAllowLAN bool
	Operators    bool
}

// ChoiceChange names the choices to change; nil leaves one as it is.
type ChoiceChange struct {
	ExitUse      *string
	AcceptRoutes *bool
	ExitAllowLAN *bool
}

// Empty reports a change that names no choice.
func (change ChoiceChange) Empty() bool {
	return change.ExitUse == nil && change.AcceptRoutes == nil && change.ExitAllowLAN == nil
}

// Choices returns the part of settings an operator sees.
func (settings Settings) Choices() Choices {
	return Choices{
		AcceptRoutes: settings.AcceptRoutes,
		ExitUse:      settings.ExitUse,
		ExitAllowLAN: settings.ExitAllowLAN,
		Operators:    settings.OperatorsAllowed(),
	}
}

// OperatorsAllowed reports whether the operators may change the Choices.
// Root's OperatorsOff always keeps them. On Linux and macOS they may by
// default: a helper writes for them and meshd cannot. On Windows meshd
// writes for them and the operators group may hold every domain user, so
// only root's OperatorsOn lets them.
func (settings Settings) OperatorsAllowed() bool {
	if settings.OperatorsOff {
		return false
	}
	return operatorsByDefault || settings.OperatorsOn
}

// WithOperators returns settings where the operators may (on) or may not
// change the Choices. Off is root's OperatorsOff, which wins everywhere.
// On clears it, and only where the operators may not by default (Windows)
// sets OperatorsOn: a file that names operators_on is one an older meshd
// or meshnetd cannot read (Decode refuses unknown fields).
func WithOperators(settings Settings, on bool) Settings {
	settings.OperatorsOff = !on
	settings.OperatorsOn = on && !operatorsByDefault
	return settings
}

// managedExitUse is what status shows for a pool the administrator
// chooses (ExitAllowManaged); no pool is named so.
const managedExitUse = "managed"

// ApplyChoices returns settings with change, valid and canonical. It
// changes nothing else: what change cannot name stays as root set it. It
// refuses (ErrRootSetting) accepting Site routes while root left public
// routes on, which would install public-range routes root never chose, and
// a value the settings do not accept (ErrInvalid).
func ApplyChoices(settings Settings, change ChoiceChange) (Settings, error) {
	if change.AcceptRoutes != nil && *change.AcceptRoutes && settings.AcceptPublicRoutes && !settings.AcceptRoutes {
		return settings, fmt.Errorf("%w: root's accept-public is on: root turns accept on", ErrRootSetting)
	}
	if change.ExitUse != nil && *change.ExitUse == managedExitUse {
		return settings, fmt.Errorf("%w: %q names no pool", ErrInvalid, managedExitUse)
	}
	if change.ExitUse != nil {
		settings.ExitUse = *change.ExitUse
		if settings.ExitUse == ExitUseOff {
			settings.ExitUse = ""
		}
	}
	if change.AcceptRoutes != nil {
		settings.AcceptRoutes = *change.AcceptRoutes
	}
	if change.ExitAllowLAN != nil {
		settings.ExitAllowLAN = *change.ExitAllowLAN
	}
	if err := settings.Validate(); err != nil {
		return settings, err
	}
	return settings.Canonical(), nil
}
