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
	cluster := clusterRuleWithGroups(t, "view", "edit")
	kubernetes, err := base.WithGroupRules([]publication.GroupRule{cluster})
	if err != nil {
		t.Fatal(err)
	}
	kubernetesRouted, err := base.WithGroupRules([]publication.GroupRule{cluster,
		groupRuleFixture(t, "000000000902", clients, servers, 22)})
	if err != nil {
		t.Fatal(err)
	}
	if kubernetesRouted, err = kubernetesRouted.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if kubernetesRouted, err = kubernetesRouted.WithExitRules([]publication.ExitRule{internet}); err != nil {
		t.Fatal(err)
	}
	// A Core before K1a3 hashes the release as if no rule named groups.
	if kubernetesRouted.LegacySemanticHash() == kubernetesRouted.SemanticHash() {
		t.Fatal("the legacy hash covers the groups")
	}
	plainCluster, err := publication.NewGroupRule(clusterRuleParams(t, policy.ProtocolTCP, 443, 443))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := base.WithGroupRules([]publication.GroupRule{plainCluster,
		groupRuleFixture(t, "000000000902", clients, servers, 22)})
	if err != nil {
		t.Fatal(err)
	}
	if legacy, err = legacy.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if legacy, err = legacy.WithExitRules([]publication.ExitRule{internet}); err != nil {
		t.Fatal(err)
	}
	if kubernetesRouted.LegacySemanticHash() != legacy.SemanticHash() {
		t.Fatal("the legacy hash differs from the release without groups")
	}
	for name, test := range map[string]struct {
		candidate publication.Candidate
		want      string
	}{
		"v1 Device pairs":              {base, pinnedDeviceReleaseHash},
		"v6 route rules":               {routed, pinnedRouteReleaseHash},
		"v7 exit rules":                {exitOnly, pinnedExitReleaseHash},
		"v7 route, exit rules":         {both, pinnedRouteExitReleaseHash},
		"v8 Kubernetes groups":         {kubernetes, pinnedKubernetesGroupsReleaseHash},
		"v8 groups, route, exit rules": {kubernetesRouted, pinnedKubernetesRouteExitReleaseHash},
	} {
		hash := test.candidate.SemanticHash().Bytes()
		if got := hex.EncodeToString(hash[:]); got != test.want {
			t.Errorf("%s: release hashes to %s, want %s", name, got, test.want)
		}
	}
}

const (
	pinnedDeviceReleaseHash              = "2f90c554774a27ad00d5abf5118a35c6509561eeab0b3a43a0dfb114d76ec8ef"
	pinnedRouteReleaseHash               = "5835f60245fdfd4c03336a63fe9b46ee4dc3be3a364ef8c26dd779772af7166e"
	pinnedExitReleaseHash                = "c7319bd0e4125d051e36ee3bbcc5e2f26d12297faa7d9d4528bccc36bcd73afb"
	pinnedRouteExitReleaseHash           = "cb2d41c272555e9465a6fb8c8f78cea94458549c8cfe6a5e212708541f7ce482"
	pinnedKubernetesGroupsReleaseHash    = "e01c966b09e6fdc731f64f227ea1420a488b02909f88061ecc76d605d5dc8d90"
	pinnedKubernetesRouteExitReleaseHash = "22b38b14c189d2de16af491a54ae7d3ed17f88b786caf0b2c000dff9b106312a"
)
