package mtcpclient

import (
	"slices"
	"strings"
	"testing"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

// A node takes its account's names (§7.13); a Kubernetes gateway never asks
// for a person's name.
func TestSelfIdentityCapability(t *testing.T) {
	t.Parallel()
	if !slices.Contains(streamCapabilities(controlplane.NetmapOptions{}, false), selfIdentityCapability) {
		t.Fatal("a node must declare self.identity1")
	}
	if slices.Contains(streamCapabilities(controlplane.NetmapOptions{}, true), selfIdentityCapability) {
		t.Fatal("a gateway must not declare self.identity1")
	}
}

// The names come from self; malformed ones are dropped, never the map.
func TestMapStateIdentity(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		identity *mtcpv1.SelfIdentity
		want     *networkmap.Identity
	}{
		"member": {
			identity: &mtcpv1.SelfIdentity{
				NetworkDisplayName: "Lab", WorkspaceDisplayName: "Acme",
				Ownership: mtcpv1.SelfIdentity_MEMBER, OwnerDisplayName: "alice@acme.example",
			},
			want: &networkmap.Identity{
				Network: "Lab", Workspace: "Acme", Ownership: networkmap.OwnershipMember,
				Owner: "alice@acme.example",
			},
		},
		"workspace": {
			identity: &mtcpv1.SelfIdentity{
				NetworkDisplayName: "Lab", WorkspaceDisplayName: "Acme",
				Ownership: mtcpv1.SelfIdentity_WORKSPACE,
			},
			want: &networkmap.Identity{Network: "Lab", Workspace: "Acme", Ownership: networkmap.OwnershipWorkspace},
		},
		"absent": {},
		"unknown ownership": {identity: &mtcpv1.SelfIdentity{
			NetworkDisplayName:   "Lab",
			WorkspaceDisplayName: "Acme",
		}},
		"a person's name on a Workspace Device": {identity: &mtcpv1.SelfIdentity{
			NetworkDisplayName:   "Lab",
			WorkspaceDisplayName: "Acme", Ownership: mtcpv1.SelfIdentity_WORKSPACE, OwnerDisplayName: "Alice",
		}},
		"control character": {identity: &mtcpv1.SelfIdentity{
			NetworkDisplayName:   "Lab\u202e",
			WorkspaceDisplayName: "Acme\n", Ownership: mtcpv1.SelfIdentity_MEMBER,
		}},
		"too long": {identity: &mtcpv1.SelfIdentity{
			NetworkDisplayName:   "Lab",
			WorkspaceDisplayName: strings.Repeat("a", 129), Ownership: mtcpv1.SelfIdentity_MEMBER,
		}},
		"no workspace": {identity: &mtcpv1.SelfIdentity{
			NetworkDisplayName: "Lab",
			Ownership:          mtcpv1.SelfIdentity_MEMBER,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			state := &mapState{self: &mtcpv1.Device{Identity: test.identity}}
			got := state.identity()
			if (got == nil) != (test.want == nil) || got != nil && *got != *test.want {
				t.Fatalf("identity() = %+v, want %+v", got, test.want)
			}
		})
	}
}
