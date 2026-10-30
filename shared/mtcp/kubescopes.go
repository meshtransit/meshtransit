package mtcp

import (
	"bytes"
	"errors"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// gateway.kube.v2 bounds (mtcp-v1 §7.12, §14).
const (
	KubernetesProfilesMaximum   = 128
	KubernetesScopesMaximum     = 256
	KubernetesScopeTableBytes   = 256 << 10
	KubernetesPeerGrantsMaximum = 64
)

// ErrKubernetesScopeTable reports a table that breaks §7.12 as a whole: the
// gateway applies the map with every peer's Kubernetes access withheld.
var ErrKubernetesScopeTable = errors.New("mtcp: invalid Kubernetes scope table")

// ValidateKubernetesScopeTable checks what makes a table unusable as a
// whole (§7.12): its bounds, and each list strictly sorted by hash. A wrong
// entry inside is that entry's error only, which the gateway judges.
func ValidateKubernetesScopeTable(table *mtcpv1.KubernetesScopeTable) error {
	if table == nil {
		return nil
	}
	if len(table.GetProfiles()) > KubernetesProfilesMaximum || len(table.GetScopes()) > KubernetesScopesMaximum ||
		proto.Size(table) > KubernetesScopeTableBytes {
		return ErrKubernetesScopeTable
	}
	for index := 1; index < len(table.GetProfiles()); index++ {
		if bytes.Compare(table.GetProfiles()[index-1].GetHash(), table.GetProfiles()[index].GetHash()) >= 0 {
			return ErrKubernetesScopeTable
		}
	}
	for index := 1; index < len(table.GetScopes()); index++ {
		if bytes.Compare(table.GetScopes()[index-1].GetHash(), table.GetScopes()[index].GetHash()) >= 0 {
			return ErrKubernetesScopeTable
		}
	}
	return nil
}
