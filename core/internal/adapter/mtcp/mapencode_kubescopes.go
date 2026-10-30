package mtcp

import (
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/shared/kubeprofile"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// encodeKubernetesScopeTable encodes a gateway's scope table (mtcp-v1
// §7.12), each list sorted by hash as the view keeps them; nil when empty.
func encodeKubernetesScopeTable(table mapsession.KubernetesScopeTable) *mtcpv1.KubernetesScopeTable {
	if table.IsEmpty() {
		return nil
	}
	encoded := &mtcpv1.KubernetesScopeTable{
		Profiles:      make([]*mtcpv1.KubernetesProfile, 0, len(table.Profiles)),
		Scopes:        make([]*mtcpv1.KubernetesScope, 0, len(table.Scopes)),
		AccessContact: table.AccessContact,
	}
	for _, profile := range table.Profiles {
		encoded.Profiles = append(encoded.Profiles, &mtcpv1.KubernetesProfile{Hash: profile.Hash[:],
			ProfileId: profile.ID, Name: profile.Profile.Name, Namespaced: encodeKubernetesProfileRules(
				profile.Profile.Namespaced), Cluster: encodeKubernetesProfileRules(profile.Profile.Cluster)})
	}
	for _, scope := range table.Scopes {
		encoded.Scopes = append(encoded.Scopes, &mtcpv1.KubernetesScope{Hash: scope.Hash[:],
			Profile: scope.Profile[:], Namespaces: scope.Namespaces, ClusterPart: scope.ClusterPart})
	}
	return encoded
}

func encodeKubernetesProfileRules(rules []kubeprofile.Rule) []*mtcpv1.KubernetesProfileRule {
	if len(rules) == 0 {
		return nil
	}
	encoded := make([]*mtcpv1.KubernetesProfileRule, len(rules))
	for index, rule := range rules {
		encoded[index] = &mtcpv1.KubernetesProfileRule{ApiGroups: rule.APIGroups, Resources: rule.Resources,
			Verbs: rule.Verbs, ResourceNames: rule.ResourceNames, NonResourceUrls: rule.NonResourceURLs}
	}
	return encoded
}

// kubernetesScopeTableOversize reports a table past the bytes a gateway
// takes: it then withholds every peer's access (§7.12). Publication bounds
// the table so this does not happen; the metric says if it did.
func kubernetesScopeTableOversize(table *mtcpv1.KubernetesScopeTable) bool {
	return table != nil && proto.Size(table) > sharedmtcp.KubernetesScopeTableBytes
}

// encodeKubernetesScopedGrants encodes a peer's scoped grants in key order.
func encodeKubernetesScopedGrants(grants []mapsession.KubernetesScopedGrant) ([]*mtcpv1.KubernetesScopedGrant,
	error) {
	if len(grants) == 0 {
		return nil, nil
	}
	encoded := make([]*mtcpv1.KubernetesScopedGrant, 0, len(grants))
	for _, grant := range grants {
		if grant.ValidUntil.UnixMilli() <= 0 {
			return nil, ErrMapEncoding
		}
		scoped := &mtcpv1.KubernetesScopedGrant{Group: grant.Group, Scope: grant.Scope[:],
			ValidUntilMs: grant.ValidUntil.UnixMilli()}
		if grant.Report {
			if grant.ReportUntil.UnixMilli() <= 0 {
				return nil, ErrMapEncoding
			}
			scoped.Mode, scoped.ReportUntilMs = mtcpv1.KubernetesScopedGrant_REPORT, grant.ReportUntil.UnixMilli()
		}
		encoded = append(encoded, scoped)
	}
	return encoded, nil
}

// kubernetesScopeTableSent counts an oversize table sent.
func (metrics *Metrics) kubernetesScopeTableSent(table *mtcpv1.KubernetesScopeTable) {
	if metrics == nil || !kubernetesScopeTableOversize(table) {
		return
	}
	metrics.kubeScopeTablesOversize.Inc()
}
