package mtcp

import (
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func identitySnapshot(t *testing.T, identity mapsession.SelfIdentity) mapsession.Snapshot {
	t.Helper()
	params := snapshotParamsFixture(t, 7, 3)
	params.SelfIdentity = identity
	return must(mapsession.NewSnapshot(params))
}

// self.identity1 (§7.13): self carries its account's names; peers never do.
func TestEncodeSelfIdentity(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		identity mapsession.SelfIdentity
		want     *mtcpv1.SelfIdentity
	}{
		"member": {
			identity: must(mapsession.NewSelfIdentity("Acme", mapsession.OwnershipMember, "alice@acme.example")),
			want: &mtcpv1.SelfIdentity{NetworkDisplayName: "Development Mesh", WorkspaceDisplayName: "Acme",
				Ownership: mtcpv1.SelfIdentity_MEMBER, OwnerDisplayName: "alice@acme.example"},
		},
		"workspace": {
			identity: must(mapsession.NewSelfIdentity("Acme", mapsession.OwnershipWorkspace, "")),
			want: &mtcpv1.SelfIdentity{NetworkDisplayName: "Development Mesh", WorkspaceDisplayName: "Acme",
				Ownership: mtcpv1.SelfIdentity_WORKSPACE},
		},
		"not negotiated": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			message, err := encodeSnapshot(identitySnapshot(t, test.identity), &mtcpv1.View{Epoch: 9, Seq: 1}, false,
				nil, dnsname.Default())
			if err != nil {
				t.Fatal(err)
			}
			got := message.GetSelf().GetIdentity()
			if (got == nil) != (test.want == nil) || got != nil && (got.GetNetworkDisplayName() !=
				test.want.GetNetworkDisplayName() || got.GetWorkspaceDisplayName() != test.want.GetWorkspaceDisplayName() ||
				got.GetOwnership() != test.want.GetOwnership() || got.GetOwnerDisplayName() != test.want.GetOwnerDisplayName()) {
				t.Fatalf("self identity = %v, want %v", got, test.want)
			}
			for _, peer := range message.GetPeers() {
				if peer.GetIdentity() != nil {
					t.Fatalf("peer %s carries an identity", peer.GetDeviceId())
				}
			}
		})
	}
}

// A delta that replaces self carries the names too: self is replaced whole.
func TestDeltaSelfCarriesSelfIdentity(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	before := must(mapsession.NewSelfIdentity("Acme", mapsession.OwnershipMember, "Alice"))
	after := must(mapsession.NewSelfIdentity("Acme Labs", mapsession.OwnershipMember, "Alice"))
	withIdentity := func(identity mapsession.SelfIdentity, revision int64) mapsession.Snapshot {
		params := snapshotParamsFixture(t, revision, 3)
		params.SelfIdentity = identity
		snapshot := must(mapsession.NewSnapshot(params))
		return must(snapshot.WithConnectivity(completeConnectivity(t, snapshot)))
	}
	current := withIdentity(before, 7)
	if err := sink.SendSnapshot(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	node.messages()
	delta := must(mapsession.NewAuthorityDelta(current, withIdentity(after, 8)))
	if err := sink.SendAuthorityDelta(t.Context(), delta); err != nil {
		t.Fatal(err)
	}
	_, message, _ := node.read()
	sent, ok := message.(*mtcpv1.MapDelta)
	if !ok {
		t.Fatalf("sent %T", message)
	}
	if got := sent.GetSelf().GetIdentity(); got.GetWorkspaceDisplayName() != "Acme Labs" ||
		got.GetOwnerDisplayName() != "Alice" {
		t.Fatalf("delta self identity = %v", got)
	}
}

// A person's name never reaches a cluster: a gateway's session never takes
// its account's names, even when it lists self.identity1.
func TestOnlyANodeSessionTakesSelfIdentity(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct{ gateway, capable, want bool }{
		"node with it":       {capable: true, want: true},
		"node without it":    {},
		"gateway with it":    {gateway: true, capable: true},
		"gateway without it": {gateway: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newConversationFixture(t, sharedmtcp.MessagePing)
			if test.gateway {
				f = gatewayFixture(t, &fakeMachineKeyRotations{})
			}
			if test.capable {
				f.session.capabilities = append(f.session.capabilities, CapabilitySelfIdentity)
			}
			f.run()
			f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
			f.streams.mu.Lock()
			requests := slices.Clone(f.streams.requests)
			f.streams.mu.Unlock()
			if len(requests) == 0 || requests[0].SelfIdentity() != test.want {
				t.Fatalf("requests %d, SelfIdentity %v", len(requests), len(requests) > 0 && requests[0].SelfIdentity())
			}
		})
	}
}

// completeConnectivity is every Device of snapshot online, as streamFixture
// sets it, so consecutive snapshots form authority deltas.
func completeConnectivity(t *testing.T, snapshot mapsession.Snapshot) []mapsession.Connectivity {
	t.Helper()
	connectivity := []mapsession.Connectivity{must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
		Key: must(mapsession.NewConnectivityKey(snapshot.NodeID(), snapshot.SessionGeneration())), Online: true,
	}))}
	for _, peer := range snapshot.AuthorizedPeers() {
		connectivity = append(connectivity, must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key: must(mapsession.NewConnectivityKey(peer.NodeID(), peer.SessionGeneration())), Online: true,
		})))
	}
	return connectivity
}

// S4c §3.3: owner_email is present only when Core read it, empty when the
// account has none, and never on a peer.
func TestEncodeSelfIdentityOwnerEmail(t *testing.T) {
	t.Parallel()
	member := must(mapsession.NewSelfIdentity("Acme", mapsession.OwnershipMember, "Alice"))
	workspace := must(mapsession.NewSelfIdentity("Acme", mapsession.OwnershipWorkspace, ""))
	for name, test := range map[string]struct {
		identity mapsession.SelfIdentity
		present  bool
		email    string
	}{
		"not read (schema 287)": {identity: member},
		"read":                  {identity: member.WithOwnerEmail("alice@example.test"), present: true, email: "alice@example.test"},
		"none":                  {identity: member.WithOwnerEmail(""), present: true},
		"invalid":               {identity: member.WithOwnerEmail("al<ice@example.test"), present: true},
		"workspace":             {identity: workspace.WithOwnerEmail("alice@example.test"), present: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			message, err := encodeSnapshot(identitySnapshot(t, test.identity), &mtcpv1.View{Epoch: 9, Seq: 1}, false,
				nil, dnsname.Default())
			if err != nil {
				t.Fatal(err)
			}
			got := message.GetSelf().GetIdentity()
			if (got.OwnerEmail != nil) != test.present || got.GetOwnerEmail() != test.email ||
				got.GetOwnerDisplayName() != test.identity.OwnerName() {
				t.Fatalf("self identity = %v", got)
			}
			for _, peer := range message.GetPeers() {
				if peer.GetIdentity() != nil {
					t.Fatalf("peer %s carries an identity", peer.GetDeviceId())
				}
			}
		})
	}
}

// An email change alone replaces self in a delta.
func TestDeltaSelfCarriesANewOwnerEmail(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	names := must(mapsession.NewSelfIdentity("Acme", mapsession.OwnershipMember, "Alice"))
	withIdentity := func(identity mapsession.SelfIdentity, revision int64) mapsession.Snapshot {
		params := snapshotParamsFixture(t, revision, 3)
		params.SelfIdentity = identity
		snapshot := must(mapsession.NewSnapshot(params))
		return must(snapshot.WithConnectivity(completeConnectivity(t, snapshot)))
	}
	current := withIdentity(names.WithOwnerEmail("old@example.test"), 7)
	if err := sink.SendSnapshot(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	node.messages()
	delta := must(mapsession.NewAuthorityDelta(current, withIdentity(names.WithOwnerEmail("new@example.test"), 8)))
	if err := sink.SendAuthorityDelta(t.Context(), delta); err != nil {
		t.Fatal(err)
	}
	_, message, _ := node.read()
	sent, ok := message.(*mtcpv1.MapDelta)
	if !ok {
		t.Fatalf("sent %T", message)
	}
	if got := sent.GetSelf().GetIdentity(); got.GetOwnerEmail() != "new@example.test" {
		t.Fatalf("delta self identity = %v", got)
	}
}
