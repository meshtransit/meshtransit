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
	// DefaultRouteSettingsPath holds the host's subnet route settings, which
	// only root writes (routesettings).
	DefaultRouteSettingsPath = "/etc/meshtransit/routes.json"
	// DefaultKubeCADir holds the Kubernetes CA files kubectl reads (K1e):
	// the package creates it for meshd, readable by every user.
	DefaultKubeCADir = "/var/lib/meshtransit/kube"
	// DefaultCaptiveWindowPath is the captive portal window root opens
	// (meshctl exit captive), in the helper's runtime directory: gone with a
	// reboot or once closed.
	DefaultCaptiveWindowPath = "/run/meshnetd/captive.json"
	// DefaultOperatorSocketPath is empty: Linux has no operators group yet,
	// so route choices stay root's (package operator).
	DefaultOperatorSocketPath = ""
)
