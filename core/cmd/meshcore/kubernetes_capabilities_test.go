package main

import (
	"slices"
	"testing"
)

// gateway.kube.v2 is offered only with gateway.kube.v1 and the profiles
// flag (K2 §27).
func TestKubernetesCapabilities(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		shared, profiles bool
		want             []string
	}{
		{false, true, nil},
		{true, false, []string{"gateway.kube.v1"}},
		{true, true, []string{"gateway.kube.v1", "gateway.kube.v2"}},
	} {
		if got := kubernetesCapabilities(test.shared, test.profiles); !slices.Equal(got, test.want) {
			t.Errorf("kubernetesCapabilities(%t, %t) = %v", test.shared, test.profiles, got)
		}
	}
}
