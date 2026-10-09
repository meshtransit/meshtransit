package distribution

import (
	"time"

	"meshtransit.net/shared/policydigest"
)

// EnforcementGrace is how long a Device may take to apply and report a newly
// delivered packet filter before a difference counts as a mismatch.
const EnforcementGrace = time.Minute

// Enforcement is how what a Device reports it enforces compares with the
// packet filter the control plane last delivered to it (R1-69).
type Enforcement string

const (
	// EnforcementEnforced reports the delivered filter, digest for digest.
	EnforcementEnforced Enforcement = "enforced"
	// EnforcementApplying was delivered a filter within EnforcementGrace and
	// has not yet reported it.
	EnforcementApplying Enforcement = "applying"
	// EnforcementMismatch reports a different filter, or none, past the grace.
	EnforcementMismatch Enforcement = "mismatch"
	// EnforcementNotReported runs a client that sends no enforcement reports.
	EnforcementNotReported Enforcement = "not_reported"
	// EnforcementUnknown has no delivered filter digest to compare with.
	EnforcementUnknown Enforcement = "unknown"
)

// FilterSummary is the policy digest of one packet filter and how many
// grants it covers; the zero value means none was recorded.
type FilterSummary struct {
	Digest policydigest.Digest
	Grants int
}

// IsZero reports that no filter was recorded.
func (filter FilterSummary) IsZero() bool { return filter == FilterSummary{} }

func (filter FilterSummary) isValid() bool {
	return filter.IsZero() ||
		!filter.Digest.IsZero() && filter.Grants >= 0 && filter.Grants <= policydigest.MaximumGrants
}

// ClassifyEnforcement compares a Device's report with its last delivery.
func ClassifyEnforcement(observation Observation, now time.Time) Enforcement {
	switch {
	case !observation.Known || observation.Filter.IsZero():
		return EnforcementUnknown
	case !observation.Enforced.IsZero() && observation.Enforced.Digest == observation.Filter.Digest:
		return EnforcementEnforced
	case now.Sub(observation.DeliveredAt) < EnforcementGrace:
		return EnforcementApplying
	case observation.Enforced.IsZero():
		return EnforcementNotReported
	default:
		return EnforcementMismatch
	}
}

func validEnforcement(observation Observation) bool {
	if !observation.Filter.isValid() || !observation.Enforced.isValid() {
		return false
	}
	if observation.Enforced.IsZero() {
		return observation.AppliedAt.IsZero() && observation.ReportedAt.IsZero()
	}
	return !observation.AppliedAt.IsZero() && !observation.ReportedAt.IsZero() &&
		!observation.AppliedAt.After(observation.ReportedAt)
}
