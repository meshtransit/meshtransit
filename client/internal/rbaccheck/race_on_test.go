//go:build race

package rbaccheck

// raceEnabled stretches wall-clock bounds: the race detector makes this
// code several times slower.
const raceEnabled = true
