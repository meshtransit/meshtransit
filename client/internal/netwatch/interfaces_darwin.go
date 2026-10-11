package netwatch

// ignorePointToPoint skips utun interfaces, whose names the kernel assigns,
// so meshd's own tunnels never count as a host network change.
const ignorePointToPoint = true
