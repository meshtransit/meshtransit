// Package buildinfo exposes bounded release metadata embedded at link time.
package buildinfo

import "runtime"

var (
	version  = "dev"
	revision = "unknown"
)

// Info is immutable, non-sensitive metadata for operator output.
type Info struct {
	Version   string
	Revision  string
	GoVersion string
}

// Current returns a caller-owned snapshot of the embedded build metadata.
func Current() Info {
	return Info{
		Version:   version,
		Revision:  revision,
		GoVersion: runtime.Version(),
	}
}

// Release returns the stable code-release identity stored with migration
// evidence. Link-time values are validated at their operator-facing boundary.
func Release() string {
	return version + "@" + revision
}
