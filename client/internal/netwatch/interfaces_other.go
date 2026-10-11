//go:build !darwin

package netwatch

// ignorePointToPoint is false where meshd names its own interfaces and
// excludes them by name.
const ignorePointToPoint = false
