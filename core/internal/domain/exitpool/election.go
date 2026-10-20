package exitpool

import (
	"time"

	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/primaryelection"
)

// ElectionHealth reads an exit node's report of its pool for the primary
// election (exit node design §8–9): when its last health report carried this
// pool, its time, so a silent exit node fails as a silent router does, and,
// while fresh, the state it gave. A report without the pool (a router's
// Sites only) counts for nothing: an exit node that never reported the pool
// is never silent, and one that fell silent is judged again by the state it
// reports for the pool once it is back.
func ElectionHealth(observation distribution.Observation, pool string, now time.Time) primaryelection.Report {
	if observation.ExitHealth == nil || observation.ExitHealth.Ref != pool {
		return primaryelection.Report{}
	}
	report := primaryelection.Report{ReportedAt: observation.RouteHealthAt}
	if health, fresh := distribution.CurrentExitHealth(observation, now); fresh {
		report.State, report.Code = health.State, health.Code
	}
	return report
}
