package main

import "os"

// environ is the process environment the analysis loads packages with.
func environ() []string { return os.Environ() }
