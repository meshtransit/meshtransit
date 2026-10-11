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
)
