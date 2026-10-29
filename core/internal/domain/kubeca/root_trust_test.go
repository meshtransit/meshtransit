package kubeca

import (
	"testing"

	"meshtransit.net/shared/kubetrust"
)

// A root Core makes is one a client trusts for its cluster's name, and an
// intermediate is not a root (mtcp-v1 §7.11): the client's check and
// constrainedCA stay one rule.
func TestClientTrustsTheRootsCoreMakes(t *testing.T) {
	t.Parallel()
	root := testRoot(t)
	if _, err := kubetrust.CheckRoot(root.Certificate().Raw, clusterName); err != nil {
		t.Fatalf("CheckRoot(a Core root) = %v", err)
	}
	intermediate := testCA(t)
	if _, err := kubetrust.CheckRoot(intermediate.Certificate().Raw, clusterName); err == nil {
		t.Fatal("an intermediate checked as a root")
	}
}
