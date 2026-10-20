package distribution

import "time"

// Address families an exit node reaches the Internet in (mtcp-v1 §7.7).
const (
	ExitFamiliesV4   = "v4"
	ExitFamiliesV6   = "v6"
	ExitFamiliesBoth = "both"
)

// ExitHealth is an exit node's health of the Exit Pool it serves, as it
// measures it itself (mtcp-v1 §8.3): State is one of the Site health states,
// Families the address families it reaches the Internet in (empty: not
// known).
type ExitHealth struct {
	Ref      string
	State    string
	Code     string
	Families string
}

// IsValid reports a pool reference and code with known state and families.
func (health ExitHealth) IsValid() bool {
	return health.Ref != "" && health.Code != "" &&
		(health.State == SiteHealthOK || health.State == SiteHealthDegraded || health.State == SiteHealthFailed) &&
		(health.Families == "" || health.Families == ExitFamiliesV4 || health.Families == ExitFamiliesV6 ||
			health.Families == ExitFamiliesBoth)
}

// CurrentExitHealth returns the exit node's pool health while it is current;
// false when it reported none or its last report is older than
// RouteHealthStale. An exit node reports its pool with its Sites, so the
// same staleness applies.
func CurrentExitHealth(observation Observation, now time.Time) (ExitHealth, bool) {
	if !observation.Known || observation.ExitHealth == nil || observation.RouteHealthAt.IsZero() ||
		now.Sub(observation.RouteHealthAt) > RouteHealthStale {
		return ExitHealth{}, false
	}
	return *observation.ExitHealth, true
}

func validExitHealth(observation Observation) bool {
	if observation.ExitHealth == nil {
		return true
	}
	return !observation.RouteHealthAt.IsZero() && observation.ExitHealth.IsValid()
}
