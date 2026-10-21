package config

// macOS paths: launchd runs meshnetd as root and meshd as _meshd. /var/run is
// cleared at boot, so meshnetd recreates both socket directories.
const (
	// DefaultSocketPath is the local control socket used by meshctl.
	DefaultSocketPath = "/var/run/meshd/meshd.sock"
	// DefaultNetAdminSocketPath is the separate privileged-helper endpoint.
	DefaultNetAdminSocketPath = "/var/run/meshnetd/meshnetd.sock"
	// DefaultStateDir contains profile metadata and encrypted identity envelopes.
	DefaultStateDir = "/Library/Application Support/MeshTransit/state"
	// DefaultIdentityKeyPath is the owner-only identity key file of meshd,
	// kept outside the state directory.
	DefaultIdentityKeyPath = "/Library/Application Support/MeshTransit/meshd.identity-key"
	// DefaultRouteSettingsPath holds the host's subnet route settings, which
	// only root writes (routesettings).
	DefaultRouteSettingsPath = "/Library/Application Support/MeshTransit/routes.json"
	// DefaultCaptiveWindowPath is the captive portal window root opens
	// (meshctl exit captive), in the helper's runtime directory: gone with a
	// reboot or once closed.
	DefaultCaptiveWindowPath = "/var/run/meshnetd/captive.json"
	// DefaultOperatorSocketPath is where meshnetd lets the meshtransit group
	// change the host's own route choices (package operator), in a directory
	// of that group.
	DefaultOperatorSocketPath = "/var/run/meshtransit/settings.sock"
)
