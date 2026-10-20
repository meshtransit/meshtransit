package mobile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"meshtransit.net/client/internal/routesettings"
)

// maximumRouteSettingsBytes bounds the settings file.
const maximumRouteSettingsBytes = 64 << 10

// routeSettingsFile holds the subnet route settings in the state directory,
// private to the app like the rest of it.
const routeSettingsFile = "routes.json"

// SetSubnetRoutes sets whether the device installs the subnet routes Core
// grants: private ranges with accept, public ones too with acceptPublic
// (which needs accept). Both are off until the person turns them on. The
// change applies within 10 seconds while connected, and is kept.
func (engine *Engine) SetSubnetRoutes(accept, acceptPublic bool) (err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return errEngineClosed
	}
	settings, err := loadRouteSettings(engine.routeSettings)
	if err != nil {
		settings = routesettings.Settings{}
	}
	settings.AcceptRoutes, settings.AcceptPublicRoutes = accept, accept && acceptPublic
	return saveRouteSettings(engine.routeSettings, settings)
}

// AcceptsSubnetRoutes reports whether the device installs the private subnet
// routes Core grants.
func (engine *Engine) AcceptsSubnetRoutes() (accepted bool, err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return false, errEngineClosed
	}
	settings, err := loadRouteSettings(engine.routeSettings)
	return settings.AcceptRoutes, err
}

// AcceptsPublicSubnetRoutes reports whether the device also installs granted
// subnet routes to public ranges.
func (engine *Engine) AcceptsPublicSubnetRoutes() (accepted bool, err error) {
	defer recoverPanic(&err)
	if engine == nil {
		return false, errEngineClosed
	}
	settings, err := loadRouteSettings(engine.routeSettings)
	return settings.AcceptRoutes && settings.AcceptPublicRoutes, err
}

// loadRouteSettings reads the app's subnet route settings; a missing file
// means everything off. The file lives in the app's private storage, which
// only the app reaches, so it needs none of the desktop ownership checks
// (routesettings.Load requires root's).
func loadRouteSettings(path string) (routesettings.Settings, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the app's own state directory
	if errors.Is(err, fs.ErrNotExist) {
		return routesettings.Settings{}, nil
	}
	if err != nil {
		return routesettings.Settings{}, fmt.Errorf("mobile: reading subnet route settings: %w", err)
	}
	defer func() { _ = file.Close() }()
	encoded, err := io.ReadAll(io.LimitReader(file, maximumRouteSettingsBytes+1))
	if err != nil {
		return routesettings.Settings{}, fmt.Errorf("mobile: reading subnet route settings: %w", err)
	}
	if len(encoded) > maximumRouteSettingsBytes {
		return routesettings.Settings{}, fmt.Errorf("%w: subnet route settings too large", errInvalidConfig)
	}
	return routesettings.Decode(encoded)
}

// saveRouteSettings replaces the app's subnet route settings atomically.
func saveRouteSettings(path string, settings routesettings.Settings) error {
	encoded, err := routesettings.Encode(settings)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".routes-*.json")
	if err != nil {
		return fmt.Errorf("mobile: writing subnet route settings: %w", err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	_, err = temporary.Write(encoded)
	err = errors.Join(err, temporary.Sync(), temporary.Close())
	if err != nil {
		return fmt.Errorf("mobile: writing subnet route settings: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("mobile: writing subnet route settings: %w", err)
	}
	return nil
}
