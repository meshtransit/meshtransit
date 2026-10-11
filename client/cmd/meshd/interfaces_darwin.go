package main

// ownInterfaces is empty on macOS: the kernel names utun interfaces, and
// netwatch ignores every point-to-point interface there.
var ownInterfaces []string
