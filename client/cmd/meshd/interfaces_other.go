//go:build !darwin

package main

// ownInterfaces are the tunnels meshnetd creates for meshd; netwatch ignores
// them.
var ownInterfaces = []string{"mesh0", "meshdns0"}
