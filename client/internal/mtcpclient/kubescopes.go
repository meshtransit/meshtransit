package mtcpclient

import (
	"bytes"
	"cmp"
	"strings"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/kubeprofile"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// compiledScopes is a gateway's scope table as it may use it (mtcp-v1
// §7.12): the usable scopes by hash, or withheld when the table is unusable
// as a whole; the counts say what was left out, for the gateway's metrics.
type compiledScopes struct {
	scopes          map[[32]byte]networkmap.KubernetesScope
	withheld        bool
	invalidProfiles int
	invalidScopes   int
}

// compileKubernetesScopes checks a table: past its bounds or out of order,
// every peer's access is withheld; a profile or scope that is wrong is left
// out alone, and with it what depends on it. An absent table holds nothing.
func compileKubernetesScopes(table *mtcpv1.KubernetesScopeTable) compiledScopes {
	compiled := compiledScopes{scopes: map[[32]byte]networkmap.KubernetesScope{}}
	if sharedmtcp.ValidateKubernetesScopeTable(table) != nil {
		return compiledScopes{withheld: true}
	}
	profiles := make(map[[32]byte]kubeprofile.Profile, len(table.GetProfiles()))
	for _, entry := range table.GetProfiles() {
		profile := convertKubernetesProfile(entry)
		hash, err := kubeprofile.ContentHash(profile)
		if err != nil || !bytes.Equal(hash[:], entry.GetHash()) {
			compiled.invalidProfiles++
			continue
		}
		profiles[hash] = profile
	}
	for _, entry := range table.GetScopes() {
		scope, hash, ok := convertKubernetesScope(entry, profiles)
		if !ok {
			compiled.invalidScopes++
			continue
		}
		compiled.scopes[hash] = scope
	}
	return compiled
}

func convertKubernetesProfile(entry *mtcpv1.KubernetesProfile) kubeprofile.Profile {
	rules := func(entries []*mtcpv1.KubernetesProfileRule) []kubeprofile.Rule {
		if len(entries) == 0 {
			return nil
		}
		out := make([]kubeprofile.Rule, len(entries))
		for index, rule := range entries {
			out[index] = kubeprofile.Rule{APIGroups: rule.GetApiGroups(), Resources: rule.GetResources(),
				Verbs: rule.GetVerbs(), ResourceNames: rule.GetResourceNames(), NonResourceURLs: rule.GetNonResourceUrls()}
		}
		return out
	}
	return kubeprofile.Profile{Name: entry.GetName(), Namespaced: rules(entry.GetNamespaced()),
		Cluster: rules(entry.GetCluster())}
}

// convertKubernetesScope checks a scope: its profile in the table, its
// namespaces strictly sorted as sent, and its hash its content's.
func convertKubernetesScope(entry *mtcpv1.KubernetesScope,
	profiles map[[32]byte]kubeprofile.Profile) (networkmap.KubernetesScope, [32]byte, bool) {
	var profileHash [32]byte
	if len(entry.GetProfile()) != len(profileHash) {
		return networkmap.KubernetesScope{}, [32]byte{}, false
	}
	copy(profileHash[:], entry.GetProfile())
	profile, found := profiles[profileHash]
	namespaces := entry.GetNamespaces()
	for index := 1; index < len(namespaces); index++ {
		if namespaces[index-1] >= namespaces[index] {
			return networkmap.KubernetesScope{}, [32]byte{}, false
		}
	}
	if !found {
		return networkmap.KubernetesScope{}, [32]byte{}, false
	}
	hash, err := kubeprofile.ScopeHash(profileHash, namespaces, entry.GetClusterPart())
	if err != nil || !bytes.Equal(hash[:], entry.GetHash()) {
		return networkmap.KubernetesScope{}, [32]byte{}, false
	}
	scope, err := kubeprofile.NewScope(profile, namespaces, entry.GetClusterPart())
	if err != nil {
		return networkmap.KubernetesScope{}, [32]byte{}, false
	}
	return networkmap.KubernetesScope{ProfileHash: profileHash, ProfileName: profile.Name, Scope: scope}, hash, true
}

// scopedKubernetesGrants converts a peer's scoped grants (mtcp-v1 §7.12).
// ok is false when they break the key order: the peer loses its access. A
// grant that allows nothing (its group not a DNS label, its scope not
// usable, its mode unknown, its report deadline wrong) is left out.
func scopedKubernetesGrants(raw []*mtcpv1.KubernetesScopedGrant,
	scopes map[[32]byte]networkmap.KubernetesScope) ([]networkmap.KubernetesScopedGrant, bool) {
	for index := 1; index < len(raw); index++ {
		if compareRawScopedGrants(raw[index-1], raw[index]) >= 0 {
			return nil, false
		}
	}
	grants := make([]networkmap.KubernetesScopedGrant, 0, len(raw))
	for _, grant := range raw {
		var scope [32]byte
		report, until, validUntil := grant.GetMode() == mtcpv1.KubernetesScopedGrant_REPORT,
			grant.GetReportUntilMs(), grant.GetValidUntilMs()
		usable := len(grant.GetScope()) == len(scope) && validUntil > 0 && networkmap.ValidKubernetesGroup(grant.GetGroup())
		switch grant.GetMode() {
		case mtcpv1.KubernetesScopedGrant_MODE_UNSPECIFIED:
			usable = usable && until == 0
		case mtcpv1.KubernetesScopedGrant_REPORT:
			usable = usable && until > 0 && until <= validUntil
		default:
			usable = false
		}
		copy(scope[:], grant.GetScope())
		if _, found := scopes[scope]; !usable || !found {
			continue
		}
		converted := networkmap.KubernetesScopedGrant{Group: grant.GetGroup(), Scope: scope, Report: report,
			ValidUntil: time.UnixMilli(validUntil).UTC()}
		if report {
			converted.ReportUntil = time.UnixMilli(until).UTC()
		}
		grants = append(grants, converted)
	}
	return grants, true
}

// compareRawScopedGrants orders grants as sent by their key: group, scope
// bytewise, mode, report deadline.
func compareRawScopedGrants(left, right *mtcpv1.KubernetesScopedGrant) int {
	if order := strings.Compare(left.GetGroup(), right.GetGroup()); order != 0 {
		return order
	}
	if order := bytes.Compare(left.GetScope(), right.GetScope()); order != 0 {
		return order
	}
	if order := cmp.Compare(left.GetMode(), right.GetMode()); order != 0 {
		return order
	}
	return cmp.Compare(left.GetReportUntilMs(), right.GetReportUntilMs())
}
