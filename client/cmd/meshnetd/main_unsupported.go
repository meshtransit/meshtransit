//go:build !linux && !darwin

// Command meshnetd owns the minimal privileged Linux TUN boundary.
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "meshnetd: the privileged helper is supported only on linux")
	os.Exit(1)
}
