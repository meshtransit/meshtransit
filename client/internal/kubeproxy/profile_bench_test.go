package kubeproxy

import (
	"fmt"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/kubeprofile"
)

// BenchmarkDecideWorstCase decides a request no rule allows through 8
// scoped grants of 16 rules each, 128 rules in all: the design's target is
// p99 under 5 µs (K2 §9.1).
func BenchmarkDecideWorstCase(b *testing.B) {
	now := time.Now()
	peer := Peer{Access: &networkmap.KubernetesAccess{}, Scopes: map[[32]byte]networkmap.KubernetesScope{}}
	for grant := range 8 {
		rules := make([]kubeprofile.Rule, 16)
		for index := range rules {
			rules[index] = kubeprofile.Rule{
				APIGroups: []string{fmt.Sprintf("group%d.example.com", index)},
				Resources: []string{"widgets", "gadgets", "gizmos/status"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
			}
		}
		profile := kubeprofile.Profile{Name: fmt.Sprintf("profile-%d", grant), Namespaced: rules}
		scope, err := kubeprofile.NewScope(profile, []string{"team-a", "team-b", "team-c"}, false)
		if err != nil {
			b.Fatal(err)
		}
		hash := [32]byte{byte(grant + 1)}
		peer.Scopes[hash] = networkmap.KubernetesScope{ProfileName: profile.Name, Scope: scope}
		peer.Access.Scoped = append(peer.Access.Scoped, networkmap.KubernetesScopedGrant{
			Group: "edit", Scope: hash, ValidUntil: now.Add(time.Hour),
		})
	}
	check := resourceCheck("delete", "apps", "deployments", "team-a", kubeprofile.ScopeNamespaced)
	group := Group{Name: "edit"}
	b.ReportAllocs()
	for b.Loop() {
		if decide(peer, group, check, now).allowed {
			b.Fatal("allowed")
		}
	}
}
