//go:build race

package main

// raceEnabled skips the whole-program analysis under the race detector: it
// is single-goroutine type checking, minutes slower with -race, and make test
// runs it without.
const raceEnabled = true
