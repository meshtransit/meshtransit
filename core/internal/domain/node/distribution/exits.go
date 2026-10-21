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

// ViaSticky is an exit node a consumer keeps although the map elected
// another (Exit Pools only, mtcp-v1 §8.3).
const ViaSticky = "sticky"

// ExitSelectionRefPrefix marks an Exit Pool's row among a node's route
// selection rows: a consumer's exit node is stored, and counted per pool,
// with its Site routers, under the pool reference with this prefix. Site
// references are public IDs and never carry it.
const ExitSelectionRefPrefix = "exit:"

// ExitSelection is the exit node a consumer reports using for one Exit Pool:
// Node a Device public ID, empty with ViaNone.
type ExitSelection struct {
	Pool string
	Node string
	Via  string
}

// CurrentExitSelection returns the consumer's exit node when reported within
// RouteSelectionStale of now; false when it reported none.
func CurrentExitSelection(observation Observation, now time.Time) (ExitSelection, bool) {
	if !observation.Known || observation.ExitSelection == nil || observation.RouteSelectionAt.IsZero() ||
		now.Sub(observation.RouteSelectionAt) > RouteSelectionStale {
		return ExitSelection{}, false
	}
	return *observation.ExitSelection, true
}

func validExitSelection(observation Observation) bool {
	exit := observation.ExitSelection
	if exit == nil {
		return true
	}
	known := exit.Via == ViaPrimary || exit.Via == ViaLocalFailover || exit.Via == ViaSticky || exit.Via == ViaNone
	return !observation.RouteSelectionAt.IsZero() && exit.Pool != "" && known && (exit.Via == ViaNone) == (exit.Node == "")
}
