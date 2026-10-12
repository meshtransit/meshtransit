package netwatch

// ignorePointToPoint skips utun interfaces, whose names the kernel assigns,
// so meshd's own tunnels never count as a host network change.
const ignorePointToPoint = true

// platformExcludedIndexes is empty: point-to-point filtering covers meshd's
// utun interfaces.
func platformExcludedIndexes() []int { return nil }
