package mtcp

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

func TestValidateKubernetesScopeTable(t *testing.T) {
	t.Parallel()
	hash := func(first byte) []byte { return append([]byte{first}, bytes.Repeat([]byte{0}, 31)...) }
	profiles := func(count int) []*mtcpv1.KubernetesProfile {
		out := make([]*mtcpv1.KubernetesProfile, count)
		for index := range out {
			out[index] = &mtcpv1.KubernetesProfile{Hash: append([]byte{byte(index >> 8), byte(index)}, bytes.Repeat([]byte{0}, 30)...)}
		}
		return out
	}
	scopes := func(count int) []*mtcpv1.KubernetesScope {
		out := make([]*mtcpv1.KubernetesScope, count)
		for index := range out {
			out[index] = &mtcpv1.KubernetesScope{Hash: append([]byte{byte(index >> 8), byte(index)}, bytes.Repeat([]byte{0}, 30)...)}
		}
		return out
	}
	for name, table := range map[string]*mtcpv1.KubernetesScopeTable{
		"absent": nil,
		"empty":  {},
		"sorted": {Profiles: []*mtcpv1.KubernetesProfile{{Hash: hash(1)}, {Hash: hash(2)}},
			Scopes: []*mtcpv1.KubernetesScope{{Hash: hash(1)}, {Hash: hash(9)}}},
		"at the bounds": {Profiles: profiles(KubernetesProfilesMaximum), Scopes: scopes(KubernetesScopesMaximum)},
		// A short hash is that entry's error, never the table's.
		"short hash": {Profiles: []*mtcpv1.KubernetesProfile{{Hash: []byte{1}}, {Hash: hash(2)}}},
	} {
		if err := ValidateKubernetesScopeTable(table); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	large := &mtcpv1.KubernetesProfile{Hash: hash(1), Name: "x", Namespaced: []*mtcpv1.KubernetesProfileRule{{
		ResourceNames: []string{strings.Repeat("n", KubernetesScopeTableBytes)}}}}
	for name, table := range map[string]*mtcpv1.KubernetesScopeTable{
		"profiles out of order": {Profiles: []*mtcpv1.KubernetesProfile{{Hash: hash(2)}, {Hash: hash(1)}}},
		"profile twice":         {Profiles: []*mtcpv1.KubernetesProfile{{Hash: hash(1)}, {Hash: hash(1)}}},
		"scopes out of order":   {Scopes: []*mtcpv1.KubernetesScope{{Hash: hash(3)}, {Hash: hash(2)}}},
		"scope twice":           {Scopes: []*mtcpv1.KubernetesScope{{Hash: hash(3)}, {Hash: hash(3)}}},
		"too many profiles":     {Profiles: profiles(KubernetesProfilesMaximum + 1)},
		"too many scopes":       {Scopes: scopes(KubernetesScopesMaximum + 1)},
		"too large":             {Profiles: []*mtcpv1.KubernetesProfile{large}},
	} {
		if err := ValidateKubernetesScopeTable(table); !errors.Is(err, ErrKubernetesScopeTable) {
			t.Errorf("%s: %v, want ErrKubernetesScopeTable", name, err)
		}
	}
}
