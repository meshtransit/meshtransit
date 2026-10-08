package config

import "strconv"

const (
	envSignupEnabled          = "MESHTRANSIT_SELF_SIGNUP_ENABLED"
	envSignupSourceDailyLimit = "MESHTRANSIT_SELF_SIGNUP_SOURCE_DAILY_LIMIT"
	envSignupHourlyLimit      = "MESHTRANSIT_SELF_SIGNUP_HOURLY_LIMIT"
)

// Default self sign-up limits: per source network each day, and per
// deployment each hour.
const (
	DefaultSignupSourceDailyLimit = 5
	DefaultSignupHourlyLimit      = 30
)

// SignupConfig turns on self sign-up: a first sign-in without an invitation
// gets its own Account and default Workspace. The database refuses it unless
// the deployment is Cloud with a current entitlement.
type SignupConfig struct {
	SourceDailyLimit int
	HourlyLimit      int
}

// loadSignupConfig returns nil unless MESHTRANSIT_SELF_SIGNUP_ENABLED is
// "true"; the limits are rejected without it.
func loadSignupConfig(lookup LookupFunc) (*SignupConfig, error) {
	enabled, present := lookup(envSignupEnabled)
	if !present || enabled == "false" {
		for _, setting := range []string{envSignupSourceDailyLimit, envSignupHourlyLimit} {
			if _, ok := lookup(setting); ok {
				return nil, settingError(setting)
			}
		}
		return nil, nil
	}
	if enabled != "true" {
		return nil, settingError(envSignupEnabled)
	}
	result := &SignupConfig{SourceDailyLimit: DefaultSignupSourceDailyLimit, HourlyLimit: DefaultSignupHourlyLimit}
	if value, ok := lookup(envSignupSourceDailyLimit); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			return nil, settingError(envSignupSourceDailyLimit)
		}
		result.SourceDailyLimit = parsed
	}
	if value, ok := lookup(envSignupHourlyLimit); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100000 {
			return nil, settingError(envSignupHourlyLimit)
		}
		result.HourlyLimit = parsed
	}
	return result, nil
}
