//go:build !windows

package main

import "os"

// entry runs meshd in the foreground; systemd and launchd supervise it.
func entry(args []string) int {
	return run(args, os.Stdout, os.Stderr)
}
