//go:build !linux

package captive

// APIURIs returns the captive portal API URIs the host's networks gave:
// none known here yet, the probes decide alone.
func APIURIs() []string { return nil }
