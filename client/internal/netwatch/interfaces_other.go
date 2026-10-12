//go:build !darwin && !windows

package netwatch

// ignorePointToPoint is false where meshd names its own interfaces and
// excludes them by name.
const ignorePointToPoint = false

// platformExcludedIndexes is empty: meshd's interfaces are excluded by name.
func platformExcludedIndexes() []int { return nil }
