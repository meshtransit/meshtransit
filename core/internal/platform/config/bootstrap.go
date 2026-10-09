package config

import "errors"

const (
	envBootstrapPlanFile = "MESHTRANSIT_BOOTSTRAP_PLAN_FILE"
	maxBootstrapPlanSize = 64 * 1024
)

// LoadBootstrapPlan reads the bounded installation accounts file named by
// MESHTRANSIT_BOOTSTRAP_PLAN_FILE. The path and contents are never formatted
// because the file names provisioned identities.
func LoadBootstrapPlan(lookup LookupFunc) ([]byte, error) {
	if lookup == nil {
		return nil, settingError(envBootstrapPlanFile)
	}
	value, present := lookup(envBootstrapPlanFile)
	if !present {
		return nil, settingError(envBootstrapPlanFile)
	}
	if err := validateFilePath(value); err != nil {
		return nil, settingError(envBootstrapPlanFile)
	}
	contents, err := readBoundedRegularFile(value, maxBootstrapPlanSize)
	if err != nil || len(contents) == 0 {
		return nil, errors.Join(ErrInvalid, settingError(envBootstrapPlanFile))
	}
	return contents, nil
}
