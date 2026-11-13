//go:build !linux && !darwin && !windows

package routesettings

// lockSettings does not lock: on the other systems (an embedding app)
// one owner writes the settings.
func lockSettings(string) (func(), error) {
	return func() {}, nil
}
