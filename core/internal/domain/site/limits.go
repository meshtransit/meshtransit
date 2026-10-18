package site

// Technical ceilings no plan can exceed: they bound maps and client state
// (mtcp-v1 §14).
const (
	MaximumRoutersPerSite  = 32
	MaximumPrefixesPerSite = 1024
	MaximumSitesPerNetwork = 1024
	MaximumProbesPerSite   = 4
)

// Limits are the plan limits of one Workspace. Paid plans set them later;
// until then every Workspace has the ceilings.
type Limits struct {
	RoutersPerSite  int
	PrefixesPerSite int
	SitesPerNetwork int
	ProbesPerSite   int
}

// Ceilings returns the technical ceilings as limits.
func Ceilings() Limits {
	return Limits{
		RoutersPerSite: MaximumRoutersPerSite, PrefixesPerSite: MaximumPrefixesPerSite,
		SitesPerNetwork: MaximumSitesPerNetwork, ProbesPerSite: MaximumProbesPerSite,
	}
}

// DefaultLimits are the limits of a Workspace without a plan.
func DefaultLimits() Limits { return Ceilings() }

// Validate accepts limits of at least one and at most the ceilings.
func (limits Limits) Validate() error {
	within := func(value, ceiling int) bool { return value >= 1 && value <= ceiling }
	if !within(limits.RoutersPerSite, MaximumRoutersPerSite) || !within(limits.PrefixesPerSite, MaximumPrefixesPerSite) ||
		!within(limits.SitesPerNetwork, MaximumSitesPerNetwork) || !within(limits.ProbesPerSite, MaximumProbesPerSite) {
		return ErrInvalid
	}
	return nil
}
