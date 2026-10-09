package mapsession

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource/catalog"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing/sharingtest"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestDirectDeviceProjectionPreservesScopeAndDirection(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := directDeviceFixture(t, policy.ProtocolICMP, nil)
	for _, self := range []Snapshot{provider, consumer} {
		params := directDeviceParams(t, self, provider, consumer, evidence)
		projection, err := NewDirectDeviceProjection(params)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := self.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		peers := mapped.AuthorizedPeers()
		if len(peers) != 1 || peers[0].Scope() != params.Peer.Scope() || peers[0].Scope() == self.Scope() ||
			len(mapped.PeerCandidates()) != 0 || len(mapped.PacketPolicy().Rules()) != 0 {
			t.Fatal("sharing widened ordinary Network inventory or policy")
		}
		rules := mapped.InboundPacketRules()
		if self.Scope() == consumer.Scope() {
			if len(rules) != 0 {
				t.Fatal("consumer gained provider initiation")
			}
		} else if len(rules) != 1 || rules[0].SourceNodeID() != consumer.NodeID() ||
			rules[0].DestinationNodeID() != provider.NodeID() || rules[0].Protocol() != policy.ProtocolICMP {
			t.Fatal("provider did not receive the exact directed inbound rule")
		}
		if !mapped.ProjectionExpiry().Equal(evidence.Authority.Endpoint.ExpiresAt()) ||
			!slices.Equal(mapped.SharingScopes(), []network.Scope{params.Peer.Scope()}) {
			t.Fatal("missing bilateral scope or expiry dependency")
		}
		if _, err := NewSnapshot(snapshotParamsWithForeignCandidate(self, params.Peer)); err == nil {
			t.Fatal("ordinary candidate reader accepted a foreign Network")
		}
	}
}

func TestDirectDeviceProjectionRejectsIndependentStaleAuthority(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := directDeviceFixture(t, policy.ProtocolICMP, nil)
	base := directDeviceParams(t, provider, provider, consumer, evidence)
	for _, test := range []struct {
		name   string
		mutate func(*DirectDeviceProjectionParams)
	}{
		{"expired endpoint", func(p *DirectDeviceProjectionParams) { p.Authority.EvaluatedAt = p.Authority.Endpoint.ExpiresAt() }},
		{"provider generation", func(p *DirectDeviceProjectionParams) { p.Authority.ProviderAuthorityGeneration++ }},
		{"consumer generation", func(p *DirectDeviceProjectionParams) { p.Authority.ConsumerAuthorityGeneration++ }},
		{"recovery epoch", func(p *DirectDeviceProjectionParams) { p.Authority.RecoveryEpoch++ }},
		{"resource version", func(p *DirectDeviceProjectionParams) { p.Authority.ResourceVersion++ }},
		{"target generation", func(p *DirectDeviceProjectionParams) { p.Authority.TargetGeneration++ }},
		{"missing export", func(p *DirectDeviceProjectionParams) { p.ProviderExport = sharing.Export{} }},
		{"missing target", func(p *DirectDeviceProjectionParams) { p.ProviderTarget = catalog.Resource{} }},
		{"inactive target", func(p *DirectDeviceProjectionParams) { p.Authority.IsResourceActive = false }},
		{"inactive import", func(p *DirectDeviceProjectionParams) { p.Authority.IsImportedResourceActive = false }},
		{"stale import", func(p *DirectDeviceProjectionParams) { p.Authority.ImportedResourceVersion++ }},
		{"missing endpoint", func(p *DirectDeviceProjectionParams) { p.Authority.Endpoint = sharing.PrivateEndpoint{} }},
		{"wrong provider revision", func(p *DirectDeviceProjectionParams) { p.ProviderNetworkRevision++ }},
		{"expired peer", func(p *DirectDeviceProjectionParams) { p.Authority.EvaluatedAt = p.Peer.KeyExpiry() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := base
			test.mutate(&params)
			if _, err := NewDirectDeviceProjection(params); !errors.Is(err, ErrInvalidDirectDeviceProjection) {
				t.Fatalf("unsafe projection: %v", err)
			}
		})
	}
}

func TestDirectDeviceProjectionRejectsAddressAndIdentityCollision(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := directDeviceFixture(t, policy.ProtocolICMP, nil)
	for _, test := range []struct {
		name   string
		mutate func(*PeerCandidateParams)
	}{
		{"same address", func(p *PeerCandidateParams) { p.Addresses = provider.Addresses() }},
		{"same numeric ID", func(p *PeerCandidateParams) { p.NumericNodeID = provider.NumericNodeID() }},
		{"same machine key", func(p *PeerCandidateParams) { p.MachineKey = provider.MachineKey() }},
		{"same node key", func(p *PeerCandidateParams) { p.NodeKey = provider.NodeKey() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := directDeviceParams(t, provider, provider, consumer, evidence)
			peer := params.Peer.params()
			test.mutate(&peer)
			var err error
			params.Peer, err = NewPeerCandidate(peer)
			if err != nil {
				t.Fatal(err)
			}
			projection, err := NewDirectDeviceProjection(params)
			if err == nil {
				_, err = provider.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
			}
			if err == nil {
				t.Fatal("ambiguous direct route accepted")
			}
		})
	}
}

func TestDirectDeviceProjectionNarrowingChangesRequireAuthorityFrame(t *testing.T) {
	t.Parallel()
	ports, err := policy.NewPortRange(80, 100)
	if err != nil {
		t.Fatal(err)
	}
	provider, consumer, evidence := directDeviceFixture(t, policy.ProtocolTCP, []policy.PortRange{ports})
	params := directDeviceParams(t, provider, provider, consumer, evidence)
	projection, err := NewDirectDeviceProjection(params)
	if err != nil {
		t.Fatal(err)
	}
	current, err := provider.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{mustDirectPort(t, 90, 95)}})
	if err != nil {
		t.Fatal(err)
	}
	params.Authority.ProviderGuardrail, err = sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	if err != nil {
		t.Fatal(err)
	}
	narrowed, err := NewDirectDeviceProjection(params)
	if err != nil {
		t.Fatal(err)
	}
	next, err := provider.WithDirectDeviceProjections([]DirectDeviceProjection{narrowed})
	if err != nil {
		t.Fatal(err)
	}
	if !streamCanAdvance(current, next) || !streamSnapshotChanged(current, next) {
		t.Fatal("same local revision hid a bilateral grant change")
	}
	if _, err := NewConnectivityDelta(current, next); !errors.Is(err, ErrInvalidConnectivityDelta) {
		t.Fatal("authority change encoded as connectivity-only")
	}
	if rules := next.InboundPacketRules(); len(rules) != 1 ||
		!slices.Equal(rules[0].DestinationPortRanges(), []policy.PortRange{mustDirectPort(t, 90, 95)}) {
		t.Fatal("provider guardrail did not narrow ports")
	}
	withdrawn, err := current.WithDirectDeviceProjections(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(withdrawn.AuthorizedPeers()) != 0 || len(withdrawn.InboundPacketRules()) != 0 ||
		!streamSnapshotChanged(current, withdrawn) {
		t.Fatal("withdrawal retained sharing")
	}
}

func snapshotParamsWithForeignCandidate(self Snapshot, peer PeerCandidate) SnapshotParams {
	params := self.params()
	params.PeerCandidates = []PeerCandidate{peer}
	return params
}

func directDeviceFixture(t *testing.T, protocol policy.Protocol, ports []policy.PortRange) (Snapshot, Snapshot, sharingtest.Evidence) {
	t.Helper()
	return directDeviceFixtureAt(t, protocol, ports, snapshotFixture(t).CreatedAt().Add(time.Hour))
}

func directDeviceFixtureAt(t *testing.T, protocol policy.Protocol, ports []policy.PortRange, now time.Time) (Snapshot, Snapshot, sharingtest.Evidence) {
	t.Helper()
	providerParams := snapshotFixture(t).params()
	providerParams.CreatedAt = now.Add(-time.Hour)
	providerParams.KeyExpiry = now.Add(time.Hour)
	provider, err := NewSnapshot(providerParams)
	if err != nil {
		t.Fatal(err)
	}
	params := provider.params()
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	params.Scope, err = network.NewScope(provider.Scope().WorkspaceID(), networkID)
	if err != nil {
		t.Fatal(err)
	}
	params.NodeID, err = node.ParseID("01890f00-0000-7000-8000-000000000702")
	if err != nil {
		t.Fatal(err)
	}
	params.NumericNodeID = 702
	params.NodeKey, err = node.NewKey([32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	params.MachineKey, err = node.NewMachineKey([32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	params.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}
	params.PacketPolicy, err = policy.NewSnapshot(policy.SnapshotParams{Scope: params.Scope, Revision: 5})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	evidence := sharingtest.New(t, sharingtest.Params{
		ProviderScope: provider.Scope(), ConsumerScope: consumer.Scope(), ProviderDeviceID: provider.NodeID(),
		ConsumerDeviceID: consumer.NodeID(), ProviderAddress: provider.Addresses()[0].Addr(),
		EvaluatedAt: provider.CreatedAt().Add(time.Hour), RecoveryEpoch: provider.RecoveryEpoch(), Protocol: protocol, Ports: ports,
	})
	return provider, consumer, evidence
}

func directDeviceParams(t *testing.T, self, provider, consumer Snapshot, evidence sharingtest.Evidence) DirectDeviceProjectionParams {
	t.Helper()
	remote := consumer
	if self.Scope() == consumer.Scope() {
		remote = provider
	}
	peerParams := peerCandidateParamsFixture(t, remote, remote.NodeID().String(), 9)
	peerParams.NodeID = remote.NodeID()
	peerParams.NumericNodeID = remote.NumericNodeID()
	peerParams.NumericOwnerID = remote.NumericOwnerID()
	peerParams.MachineKey = remote.MachineKey()
	peerParams.NodeKey = remote.NodeKey()
	peerParams.SessionGeneration = remote.SessionGeneration()
	peerParams.Addresses = remote.Addresses()
	peerParams.CreatedAt = remote.CreatedAt()
	peerParams.KeyExpiry = remote.KeyExpiry()
	peer, err := NewPeerCandidate(peerParams)
	if err != nil {
		t.Fatal(err)
	}
	return DirectDeviceProjectionParams{Self: self, Peer: peer, ProviderTarget: evidence.Target, ProviderExport: evidence.Export, Authority: evidence.Authority,
		ConsumerRule: evidence.Rule, ProviderNetworkRevision: provider.NetworkRevision(),
		ConsumerNetworkRevision: consumer.NetworkRevision(), ConsumerPolicyRevision: consumer.PacketPolicy().Revision()}
}

func mustDirectPort(t *testing.T, first, last uint16) policy.PortRange {
	t.Helper()
	value, err := policy.NewPortRange(first, last)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDirectDeviceProjectionRejectsThirdNetworkAndCrossWorkspace(t *testing.T) {
	t.Parallel()
	provider, consumer, evidence := directDeviceFixture(t, policy.ProtocolICMP, nil)
	third := provider.params()
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000203")
	if err != nil {
		t.Fatal(err)
	}
	third.Scope, err = network.NewScope(provider.Scope().WorkspaceID(), networkID)
	if err != nil {
		t.Fatal(err)
	}
	third.PacketPolicy, err = policy.NewSnapshot(policy.SnapshotParams{Scope: third.Scope, Revision: 5})
	if err != nil {
		t.Fatal(err)
	}
	thirdSelf, err := NewSnapshot(third)
	if err != nil {
		t.Fatal(err)
	}
	params := directDeviceParams(t, provider, provider, consumer, evidence)
	params.Self = thirdSelf
	if _, err := NewDirectDeviceProjection(params); err == nil {
		t.Fatal("third Network inherited sharing")
	}
	foreign := consumer.params()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	if err != nil {
		t.Fatal(err)
	}
	foreign.Scope, err = network.NewScope(workspaceID, foreign.Scope.NetworkID())
	if err != nil {
		t.Fatal(err)
	}
	foreign.PacketPolicy, err = policy.NewSnapshot(policy.SnapshotParams{Scope: foreign.Scope, Revision: 5})
	if err != nil {
		t.Fatal(err)
	}
	foreignSelf, err := NewSnapshot(foreign)
	if err != nil {
		t.Fatal(err)
	}
	params = directDeviceParams(t, provider, provider, consumer, evidence)
	peer := params.Peer.params()
	peer.Scope = foreignSelf.Scope()
	params.Peer, err = NewPeerCandidate(peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectDeviceProjection(params); err == nil {
		t.Fatal("foreign Workspace used direct endpoint")
	}
	projection, err := NewDirectDeviceProjection(directDeviceParams(t, consumer, provider, consumer, evidence))
	if err != nil {
		t.Fatal(err)
	}
	imported, err := consumer.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	params = directDeviceParams(t, consumer, provider, consumer, evidence)
	params.Self = imported
	if _, err := NewDirectDeviceProjection(params); err == nil {
		t.Fatal("existing import became new source authority")
	}
}

func TestDirectDeviceExpiryReconstructsMapWithoutEndingSelf(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider, consumer, evidence := directDeviceFixtureAt(t, policy.ProtocolICMP, nil, time.Now())
		evidence.Authority.Endpoint = shortDirectEndpoint(t, evidence.Authority, time.Now().Add(2*time.Second))
		projection, err := NewDirectDeviceProjection(directDeviceParams(t, provider, provider, consumer, evidence))
		if err != nil {
			t.Fatal(err)
		}
		initial, err := provider.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, initial, provider}}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		sink := &recordingStreamSink{}
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		snapshots, _ := sink.state()
		if len(snapshots) != 2 || len(snapshots[1].AuthorizedPeers()) != 0 ||
			len(snapshots[1].InboundPacketRules()) != 0 || len(sink.authorityWithdrawals()) != 0 {
			t.Fatal("expiry retained sharing or ended the live self Device")
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestDirectDeviceExpiryWithdrawsOnUnavailableAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider, consumer, evidence := directDeviceFixtureAt(t, policy.ProtocolICMP, nil, time.Now())
		evidence.Authority.Endpoint = shortDirectEndpoint(t, evidence.Authority, time.Now().Add(2*time.Second))
		projection, err := NewDirectDeviceProjection(directDeviceParams(t, provider, provider, consumer, evidence))
		if err != nil {
			t.Fatal(err)
		}
		initial, err := provider.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial}, failures: []error{nil, nil, errors.New("controlled authoritative read failure")}}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		sink := &recordingStreamSink{}
		machine, request := authenticatedRequestFixture(t, initial)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if len(sink.authorityWithdrawals()) != 1 {
			t.Fatal("failed reload retained expired sharing")
		}
		if err := <-result; !errors.Is(err, ErrStreamUnavailable) {
			t.Fatal(err)
		}
	})
}

func shortDirectEndpoint(t *testing.T, authority sharing.EffectiveAccessParams, expiresAt time.Time) sharing.PrivateEndpoint {
	t.Helper()
	original := authority.Endpoint
	endpoint, err := sharing.NewPrivateEndpoint(sharing.PrivateEndpointParams{
		ID: original.ID(), Contract: authority.Contract, AccessName: original.AccessName(),
		Mode: sharing.EndpointModeDirect, ResourceAlias: original.ResourceAlias(), Generation: original.Generation(),
		ImportedResourceVersion: original.ImportedResourceVersion(), Grant: original.Grant(), ExpiresAt: expiresAt,
		State: sharing.EndpointStateReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func TestDirectDeviceReadFailureWithdrawsBeforeGrantExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider, consumer, evidence := directDeviceFixtureAt(t, policy.ProtocolICMP, nil, time.Now())
		projection, err := NewDirectDeviceProjection(directDeviceParams(t, provider, provider, consumer, evidence))
		if err != nil {
			t.Fatal(err)
		}
		initial, err := provider.WithDirectDeviceProjections([]DirectDeviceProjection{projection})
		if err != nil {
			t.Fatal(err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial}, failures: []error{nil, nil, errors.New("controlled bilateral read failure")}}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		service.options.ReconcileInterval = 2 * time.Second
		sink := &recordingStreamSink{}
		machine, request := authenticatedRequestFixture(t, initial)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, sink) }()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if !initial.ProjectionExpiry().After(time.Now()) || len(sink.authorityWithdrawals()) != 1 {
			t.Fatal("failed bilateral read retained unexpired sharing authority")
		}
		if err := <-result; !errors.Is(err, ErrStreamUnavailable) {
			t.Fatal(err)
		}
	})
}
