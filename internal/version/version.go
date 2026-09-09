// Package version exposes build metadata injected by the release pipeline.
package version

import "fmt"

var (
	// Version is the semantic version of the binary.
	Version = "dev"
	// Commit is the source revision used to build the binary.
	Commit = "none"
	// Date is the UTC build timestamp.
	Date = "unknown"
)

// Info is the stable representation returned by the local API.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Current returns an immutable copy of the current build metadata.
func Current() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
	}
}

// String returns build metadata in a compact human-readable form.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date)
}
