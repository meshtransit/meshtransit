//go:build windows

package config

const (
	// DefaultSocketPath is the local control pipe used by meshctl. Only
	// Administrators and SYSTEM can create a pipe under ProtectedPrefix, so
	// no unprivileged process can take the name first.
	DefaultSocketPath = `\\.\pipe\ProtectedPrefix\Administrators\MeshTransit\meshd`
	// DefaultNetAdminSocketPath is unused on Windows: one service owns the
	// adapter, routes and DNS, because a Wintun session cannot be handed to
	// another process.
	DefaultNetAdminSocketPath = `\\.\pipe\ProtectedPrefix\Administrators\MeshTransit\meshnetd`
	// DefaultStateDir contains profile metadata and encrypted identity envelopes.
	DefaultStateDir = `C:\ProgramData\MeshTransit\state`
	// DefaultIdentityKeyPath is the DPAPI-protected identity key.
	DefaultIdentityKeyPath = `C:\ProgramData\MeshTransit\meshd.identity-key`
	// DefaultRouteSettingsPath holds the host's subnet route settings, which
	// only SYSTEM and administrators write (routesettings).
	DefaultRouteSettingsPath = `C:\ProgramData\MeshTransit\routes.json`
)
