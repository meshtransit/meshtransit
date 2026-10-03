package mapsession

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/sharing/sharingtest"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestDeviceAliasProjectionSupportsOverlappingCanonicalAddresses(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := deviceAliasFixture(t)
	for _, self := range []Snapshot{provider, consumer} {
		params := deviceAliasProjectionParams(t, self, provider, consumer, evidence)
		projection, err := NewDirectDeviceProjection(params)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := self.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		peers := mapped.AuthorizedPeers()
		if len(peers) != 1 || !slices.Equal(peers[0].Addresses(), params.Aliases.RemoteAddresses()) ||
			len(mapped.PeerCandidates()) != 0 || len(mapped.PacketPolicy().Rules()) != 0 {
			t.Fatal("alias merged ordinary inventory or exposed canonical foreign addresses")
		}
		grant, ok := mapped.DeviceAliasFor(peers[0].NodeID())
		if !ok || grant.GrantRevision != 14 || grant.IsConsumer != (self.Scope() == consumer.Scope()) ||
			grant.SelfKey != self.NodeKey() || grant.PeerKey != peers[0].NodeKey() ||
			!grant.Traffic.Allows(policy.ProtocolTCP, 8443) || grant.Traffic.Allows(policy.ProtocolTCP, 8444) {
			t.Fatal("invalid exact peer grant")
		}
		if len(mapped.InboundPacketRules()) != map[bool]int{true: 0, false: 1}[grant.IsConsumer] {
			t.Fatal("reverse rule granted")
		}
		if mapped.ProjectionExpiry() != projection.ExpiresAt() || len(mapped.SharingScopes()) != 1 {
			t.Fatal("missing withdrawal deadline or dependency")
		}
		grant.LocalAddresses[0] = netip.MustParsePrefix("100.99.0.1/32")
		next, _ := mapped.DeviceAliasFor(peers[0].NodeID())
		if next.LocalAddresses[0] == grant.LocalAddresses[0] {
			t.Fatal("grant aliases mutable")
		}
	}
}

func TestDeviceAliasProjectionRejectsIndependentStaleOrAmbiguousEvidence(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := deviceAliasFixture(t)
	tests := []struct {
		name   string
		mutate func(*DirectDeviceProjectionParams)
	}{
		{"missing pair", func(p *DirectDeviceProjectionParams) { p.Aliases = DeviceAlias{} }},
		{"wrong self key", func(p *DirectDeviceProjectionParams) { p.Aliases.params.SelfKey = p.Peer.NodeKey() }},
		{"stale session", func(p *DirectDeviceProjectionParams) { p.Aliases.params.PeerSessionGeneration++ }},
		{"stale generation", func(p *DirectDeviceProjectionParams) { p.Aliases.params.Generation++ }},
		{"recovery mismatch", func(p *DirectDeviceProjectionParams) { p.Aliases.params.RecoveryEpoch++ }},
		{"expiry extension", func(p *DirectDeviceProjectionParams) { p.Aliases.params.ExpiresAt = p.Self.KeyExpiry() }},
		{"raw remote", func(p *DirectDeviceProjectionParams) { p.peerAddresses(t, provider.Addresses()) }},
		{"local collision", func(p *DirectDeviceProjectionParams) { p.Aliases.params.LocalAddresses = consumer.Addresses() }},
		{"partial family", func(p *DirectDeviceProjectionParams) {
			p.Aliases.params.RemoteAddresses = p.Aliases.params.RemoteAddresses[:1]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := deviceAliasProjectionParams(t, consumer, provider, consumer, evidence)
			test.mutate(&p)
			if _, err := NewDirectDeviceProjection(p); err == nil {
				t.Fatal("unsafe evidence admitted")
			}
		})
	}
}

func (params *DirectDeviceProjectionParams) peerAddresses(t *testing.T, addresses []netip.Prefix) {
	t.Helper()
	p := params.Peer.params()
	p.Addresses = addresses
	peer, err := NewPeerCandidate(p)
	if err != nil {
		t.Fatal(err)
	}
	params.Peer = peer
}

func deviceAliasFixture(t *testing.T) (Snapshot, Snapshot, sharingtest.Evidence) {
	t.Helper()
	provider, consumer, _ := directDeviceFixture(t, policy.ProtocolTCP, []policy.PortRange{mustDirectPort(t, 8443, 8443)})
	pp := provider.params()
	pp.Addresses = append(pp.Addresses, netip.MustParsePrefix("fd00:10::1/128"))
	var err error
	provider, err = NewSnapshot(pp)
	if err != nil {
		t.Fatal(err)
	}
	cp := consumer.params()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	if err != nil {
		t.Fatal(err)
	}
	cp.Scope, err = network.NewScope(workspaceID, cp.Scope.NetworkID())
	if err != nil {
		t.Fatal(err)
	}
	cp.PacketPolicy, err = policy.NewSnapshot(policy.SnapshotParams{Scope: cp.Scope, Revision: 5})
	if err != nil {
		t.Fatal(err)
	}
	cp.Addresses = provider.Addresses()
	consumer, err = NewSnapshot(cp)
	if err != nil {
		t.Fatal(err)
	}
	evidence := sharingtest.New(t, sharingtest.Params{ProviderScope: provider.Scope(), ConsumerScope: consumer.Scope(),
		ProviderDeviceID: provider.NodeID(), ConsumerDeviceID: consumer.NodeID(), ProviderAddress: netip.MustParseAddr("100.96.0.1"),
		EvaluatedAt: provider.CreatedAt().Add(time.Hour), RecoveryEpoch: provider.RecoveryEpoch(), Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{mustDirectPort(t, 8443, 8443)}})
	return provider, consumer, evidence
}

func deviceAliasProjectionParams(t *testing.T, self, provider, consumer Snapshot, evidence sharingtest.Evidence) DirectDeviceProjectionParams {
	t.Helper()
	p := directDeviceParams(t, self, provider, consumer, evidence)
	resource := []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32"), netip.MustParsePrefix("fd00:feed::1/128")}
	source := []netip.Prefix{netip.MustParsePrefix("100.96.1.1/32"), netip.MustParsePrefix("fd00:feed:1::1/128")}
	local, remote := resource, source
	if self.Scope() == consumer.Scope() {
		local, remote = source, resource
	}
	p.peerAddresses(t, remote)
	aliases, err := NewDeviceAlias(DeviceAliasParams{ContractID: evidence.Authority.Contract.ID(), EndpointID: evidence.Authority.Endpoint.ID(),
		Generation: evidence.Authority.Endpoint.Generation(), RecoveryEpoch: self.RecoveryEpoch(), SelfKey: self.NodeKey(), PeerKey: p.Peer.NodeKey(),
		SelfSessionGeneration: self.SessionGeneration(), PeerSessionGeneration: p.Peer.SessionGeneration(), LocalAddresses: local, RemoteAddresses: remote, ExpiresAt: evidence.Authority.Endpoint.ExpiresAt()})
	if err != nil {
		t.Fatal(err)
	}
	p.Aliases = aliases
	return p
}
