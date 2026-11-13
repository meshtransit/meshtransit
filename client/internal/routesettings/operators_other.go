//go:build !windows

package routesettings

// operatorsByDefault lets the operators change their choices unless root
// turns OperatorsOff on: a helper writes for them, never meshd.
const operatorsByDefault = true
