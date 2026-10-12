//go:build !darwin && !windows

package cli

const defaultSocketPath = "/run/meshd/meshd.sock"
