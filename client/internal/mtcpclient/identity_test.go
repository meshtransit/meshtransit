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

// S4c §4: the owner's email is read on its own; a bad one, or one on a
// Workspace's Device, reads as none and keeps the names.
func TestMapStateIdentityEmail(t *testing.T) {
	t.Parallel()
	email := func(value string) *string { return &value }
	member := func(ownerEmail *string) *mtcpv1.SelfIdentity {
		return &mtcpv1.SelfIdentity{
			NetworkDisplayName: "Lab", WorkspaceDisplayName: "Acme",
			Ownership: mtcpv1.SelfIdentity_MEMBER, OwnerDisplayName: "Alice", OwnerEmail: ownerEmail,
		}
	}
	for name, test := range map[string]struct {
		identity    *mtcpv1.SelfIdentity
		email       string
		known, kept bool
	}{
		"an older Core":    {identity: member(nil), kept: true},
		"email":            {identity: member(email("alice@example.test")), email: "alice@example.test", known: true, kept: true},
		"none":             {identity: member(email("")), known: true, kept: true},
		"bidi":             {identity: member(email("al\u202eice@example.test")), known: true, kept: true},
		"angle bracket":    {identity: member(email("al>ice@example.test")), known: true, kept: true},
		"utf-8":            {identity: member(email("ålice@example.test")), known: true, kept: true},
		"no dot in domain": {identity: member(email("alice@localhost")), known: true, kept: true},
		"workspace's Device": {
			identity: &mtcpv1.SelfIdentity{
				NetworkDisplayName: "Lab", WorkspaceDisplayName: "Acme", Ownership: mtcpv1.SelfIdentity_WORKSPACE,
				OwnerEmail: email("alice@example.test"),
			},
			known: true, kept: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := (&mapState{self: &mtcpv1.Device{Identity: test.identity}}).identity()
			if (got != nil) != test.kept || got != nil && (got.Email != test.email || got.EmailKnown != test.known ||
				got.Workspace != "Acme") {
				t.Fatalf("identity() = %+v", got)
			}
		})
	}
}
