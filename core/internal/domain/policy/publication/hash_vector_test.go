package publication_test

import (
	"encoding/hex"
	"testing"

	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// TestReleaseHashesStayStable pins the semantic hash of releases of each
// hash domain: stored releases are compared against it on every
// simulation and republication, so a change to their encoding must be a new
// hash domain, never an edit of an existing one.
func TestReleaseHashesStayStable(t *testing.T) {
	t.Parallel()
	clients, servers := mustGroupID(t, "000000000a01"), mustGroupID(t, "000000000a02")
	direct := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{direct})
	withGroups, err := base.WithGroupRules([]publication.GroupRule{groupRuleFixture(t, "000000000901", clients, servers, 22)})
	if err != nil {
		t.Fatal(err)
	}
	routed, err := withGroups.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	internet := exitRuleFixture(t, "000000000d01", clients, "000000000e01", 443)
	exitOnly, err := base.WithExitRules([]publication.ExitRule{internet})
	if err != nil {
		t.Fatal(err)
	}
	both, err := routed.WithExitRules([]publication.ExitRule{internet})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		candidate publication.Candidate
		want      string
	}{
		"v1 Device pairs":      {base, pinnedDeviceReleaseHash},
		"v6 route rules":       {routed, pinnedRouteReleaseHash},
		"v7 exit rules":        {exitOnly, pinnedExitReleaseHash},
		"v7 route, exit rules": {both, pinnedRouteExitReleaseHash},
	} {
		hash := test.candidate.SemanticHash().Bytes()
		if got := hex.EncodeToString(hash[:]); got != test.want {
			t.Errorf("%s: release hashes to %s, want %s", name, got, test.want)
		}
	}
}

const (
	pinnedDeviceReleaseHash    = "2f90c554774a27ad00d5abf5118a35c6509561eeab0b3a43a0dfb114d76ec8ef"
	pinnedRouteReleaseHash     = "5835f60245fdfd4c03336a63fe9b46ee4dc3be3a364ef8c26dd779772af7166e"
	pinnedExitReleaseHash      = "c7319bd0e4125d051e36ee3bbcc5e2f26d12297faa7d9d4528bccc36bcd73afb"
	pinnedRouteExitReleaseHash = "cb2d41c272555e9465a6fb8c8f78cea94458549c8cfe6a5e212708541f7ce482"
)
