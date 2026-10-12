//go:build !darwin && !windows

package config

const (
	// DefaultSocketPath is the local control socket used by meshctl.
	DefaultSocketPath = "/run/meshd/meshd.sock"
	// DefaultNetAdminSocketPath is the separate privileged-helper endpoint.
	DefaultNetAdminSocketPath = "/run/meshnetd/meshnetd.sock"
	// DefaultStateDir contains profile metadata and encrypted identity envelopes.
	DefaultStateDir = "/var/lib/meshd"
	// DefaultIdentityKeyPath is the systemd credential exposed to meshd.
	DefaultIdentityKeyPath = "/run/credentials/meshd.service/meshd.identity-key"
)
