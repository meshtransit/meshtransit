package kubecluster_test

import (
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func TestValidKubernetesGroup(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"view": true, "debug-pods": true, "a": true, "0": true, strings.Repeat("a", 63): true,
		"": false, strings.Repeat("a", 64): false, "View": false, "-view": false, "view-": false,
		"read_only": false, "view.all": false, "system:masters": false, "vïew": false,
	} {
		if got := kubecluster.ValidKubernetesGroup(name); got != want {
			t.Errorf("ValidKubernetesGroup(%q) = %t, want %t", name, got, want)
		}
	}
}
