package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"meshtransit.net/client/internal/routesettings"
)

var (
	// ErrRouteChoicesUnavailable reports a host without route settings, or
	// settings that cannot be read (unsafe or malformed): root fixes them.
	ErrRouteChoicesUnavailable = errors.New("daemon: the route settings cannot be read")
	// ErrRouteChoicesReadOnly reports a host where meshd may not write the
	// route settings: a helper (meshnetd) or root changes them.
	ErrRouteChoicesReadOnly = errors.New("daemon: meshd does not change the route settings on this host")
	// ErrOperatorsOff reports an operator's change while root keeps the
	// choices (routesettings.Settings.OperatorsAllowed).
	ErrOperatorsOff = errors.New("daemon: root keeps the route choices")
	// ErrExitPoolNotGranted reports an Exit Pool the Network does not grant
	// this node: taken, it would drop the host's Internet traffic behind
	// the kill switch with no exit node to carry it (TD-CLI-120).
	ErrExitPoolNotGranted = errors.New("daemon: the Network grants no Exit Pool by that name")
)

// RouteChoices are the host's own route choices and whether the caller may
// change them.
type RouteChoices struct {
	routesettings.Choices
	CanChange bool
}

// RouteChoices reads the host's own route choices (exit node design §11)
// for a caller who is an administrator or not.
func (s *Service) RouteChoices(_ context.Context, administrator bool) (RouteChoices, error) {
	if s.routeSettingsPath == "" {
		return RouteChoices{}, ErrRouteChoicesUnavailable
	}
	settings, err := s.loadRouteSettings(s.routeSettingsPath)
	if err != nil {
		s.routeLogger().Warn("route settings unreadable for the route choices", "error", err)
		return RouteChoices{}, ErrRouteChoicesUnavailable
	}
	return s.routeChoicesOf(settings, administrator), nil
}

// ChangeRouteChoices changes the host's own route choices where meshd
// writes the route settings (Windows, where it runs as SYSTEM). An
// administrator always may; an operator only while root lets them, which
// is read again under the settings' lock. meshd never creates or
// re-permissions the settings directory for it (routesettings.
// UpdateExisting), and a file that cannot be read is never started over:
// root fixes both with meshctl routes.
func (s *Service) ChangeRouteChoices(
	_ context.Context, change routesettings.ChoiceChange, administrator bool,
) (RouteChoices, error) {
	if !s.routeChoicesWritable {
		return RouteChoices{}, ErrRouteChoicesReadOnly
	}
	if s.routeSettingsPath == "" {
		return RouteChoices{}, ErrRouteChoicesUnavailable
	}
	if change.Empty() {
		return RouteChoices{}, fmt.Errorf("%w: no choice named", routesettings.ErrInvalid)
	}
	if !administrator {
		// Read first, touching nothing: while root keeps the choices an
		// operator makes meshd neither lock nor write (review H2).
		current, err := s.loadRouteSettings(s.routeSettingsPath)
		if err != nil {
			s.routeLogger().Warn("route settings unreadable; not changing the route choices", "error", err)
			return RouteChoices{}, ErrRouteChoicesUnavailable
		}
		if !current.OperatorsAllowed() {
			return RouteChoices{}, ErrOperatorsOff
		}
	}
	saved, err := s.updateRouteSettings(s.routeSettingsPath, func(current routesettings.Settings, loadErr error) (
		routesettings.Settings, error,
	) {
		if loadErr != nil {
			s.routeLogger().Warn("route settings unreadable; not changing the route choices", "error", loadErr)
			return current, ErrRouteChoicesUnavailable
		}
		if !administrator && !current.OperatorsAllowed() {
			return current, ErrOperatorsOff
		}
		next, err := routesettings.ApplyChoices(current, change)
		if err != nil {
			return current, err
		}
		// After the operator gate and the value's own checks: a pool the
		// Network does not grant would drop the host's Internet traffic.
		if change.ExitUse != nil && !s.exitPoolGranted(next.ExitUse) {
			return current, ErrExitPoolNotGranted
		}
		return next, nil
	})
	if err != nil {
		if !errors.Is(err, ErrRouteChoicesUnavailable) && !errors.Is(err, ErrOperatorsOff) &&
			!errors.Is(err, routesettings.ErrRootSetting) && !errors.Is(err, routesettings.ErrInvalid) &&
			!errors.Is(err, ErrExitPoolNotGranted) {
			s.routeLogger().Error("writing the route choices failed", "error", err)
			return RouteChoices{}, fmt.Errorf("%w: %w", ErrRouteChoicesUnavailable, err)
		}
		return RouteChoices{}, err
	}
	return s.routeChoicesOf(saved, administrator), nil
}

// routeLogger is the service's logger, or one that discards.
func (s *Service) routeLogger() *slog.Logger {
	if s.logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.logger
}

func (s *Service) routeChoicesOf(settings routesettings.Settings, administrator bool) RouteChoices {
	choices := settings.Choices()
	return RouteChoices{
		Choices:   choices,
		CanChange: s.routeChoicesWritable && (administrator || choices.Operators),
	}
}
