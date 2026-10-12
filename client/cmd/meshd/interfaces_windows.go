//go:build windows

package main

// ownInterfaces are the MeshTransit links that host network watching
// ignores; on Windows that is the Wintun adapter.
var ownInterfaces = []string{"MeshTransit"}
