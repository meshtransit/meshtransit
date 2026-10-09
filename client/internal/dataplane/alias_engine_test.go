package dataplane

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/networkmap"
	"github.com/meshtransit/meshtransit/client/internal/relay"
)

type aliasTransitionFactory struct {
	device *aliasTransitionDevice
}

type aliasTransitionDevice struct {
	fakeWireGuardDevice
	filter    *policyFilter
	packet    []byte
	violation bool
	file      *os.File
}

func (f *aliasTransitionFactory) New(
	_ context.Context,
	file *os.File,
	_ int,
	filter *policyFilter,
	_ PacketObserver,
	_ *relay.Config,
) (wireGuardDevice, error) {
	f.device.filter = filter
	f.device.file = file
	return f.device, nil
}

func (d *aliasTransitionDevice) Configure(reader io.Reader) error {
	if d.filter.ProcessPacket(PacketOutbound, append([]byte{}, d.packet...)) {
		d.violation = true
	}
	return d.fakeWireGuardDevice.Configure(reader)
}

func (d *aliasTransitionDevice) Close() {
	d.fakeWireGuardDevice.Close()
	if d.file != nil {
		_ = d.file.Close()
	}
}

func TestAliasEnginePausesAdmissionThroughSuccessAndFailure(t *testing.T) {
	t.Parallel()
	privateKey, original := testWireGuardSnapshot(t)
	snapshot, now := aliasPolicySnapshot(networkmap.AliasConsumer)
	snapshot.Self.PublicKey = original.Self.PublicKey
	snapshot.Peers[0].PublicKey = original.Peers[0].PublicKey
	snapshot.Peers[0].Endpoints = append([]netip.AddrPort{}, original.Peers[0].Endpoints...)
	snapshot.Peers[0].Alias.SelfKey = snapshot.Self.PublicKey
	snapshot.Peers[0].Alias.PeerKey = snapshot.Peers[0].PublicKey
	vector := aliasRoundtripVectors(t)[0]
	device := &aliasTransitionDevice{packet: aliasPacket(t, vector.ConsumerKernel)}
	factory := &aliasTransitionFactory{device: device}
	engine, err := newWireGuardEngine(&wireGuardTUNOpener{}, 41641, factory, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	engine.clock = func() time.Time { return now }
	engine.filter.clock = engine.clock
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	if device.violation {
		t.Fatal("initial configuration admitted alias traffic")
	}
	assertAliasPacket(t, engine.filter, PacketOutbound, aliasPacket(t, vector.ConsumerKernel), vector.ConsumerWire)
	snapshot.Revision++
	snapshot.Peers[0].Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.21:41641")}
	snapshot.Peers[0].Alias.GrantRevision++
	device.configureErr = errors.New("injected configuration failure")
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err == nil {
		t.Fatal("injected failure ignored")
	}
	if device.violation {
		t.Fatal("replacement admitted traffic before configuration completed")
	}
	if device.closeCalls == 0 {
		t.Fatal("ambiguous device was not closed")
	}
	if engine.filter.ProcessPacket(PacketOutbound, aliasPacket(t, vector.ConsumerKernel)) {
		t.Fatal("failed transition retained packet authority")
	}
}
