package site

import (
	"errors"
	"testing"
)

func TestLimitsDefaultToTheCeilings(t *testing.T) {
	t.Parallel()
	limits := DefaultLimits()
	if limits != Ceilings() || limits.RoutersPerSite != 32 || limits.PrefixesPerSite != 1024 ||
		limits.SitesPerNetwork != 1024 || limits.ProbesPerSite != 4 {
		t.Fatalf("DefaultLimits() = %+v", limits)
	}
}

func TestLimitsStayUnderTheCeilings(t *testing.T) {
	t.Parallel()
	for name, limits := range map[string]Limits{
		"zero":          {},
		"routers high":  {RoutersPerSite: 33, PrefixesPerSite: 1, SitesPerNetwork: 1, ProbesPerSite: 1},
		"prefixes high": {RoutersPerSite: 1, PrefixesPerSite: 1025, SitesPerNetwork: 1, ProbesPerSite: 1},
		"sites high":    {RoutersPerSite: 1, PrefixesPerSite: 1, SitesPerNetwork: 1025, ProbesPerSite: 1},
		"probes high":   {RoutersPerSite: 1, PrefixesPerSite: 1, SitesPerNetwork: 1, ProbesPerSite: 5},
	} {
		if err := limits.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Validate() = %v", name, err)
		}
	}
	plan := Limits{RoutersPerSite: 2, PrefixesPerSite: 8, SitesPerNetwork: 3, ProbesPerSite: 1}
	if err := plan.Validate(); err != nil {
		t.Fatalf("a small plan = %v", err)
	}
}
