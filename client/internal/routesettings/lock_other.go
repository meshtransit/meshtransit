//go:build !linux && !darwin

package routesettings

// lockSettings does not lock: where no operator socket runs, only
// administrators write the settings, one command at a time.
func lockSettings(string) (func(), error) {
	return func() {}, nil
}
