//go:build linux || darwin || windows

package dataplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"meshtransit.net/client/internal/interchange"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/netcheck"
)

type officialWireGuardFactory struct {
	generations *socketGenerationSource
	credentials *relayCredentials
	logger      *slog.Logger
}

type officialWireGuardDevice struct {
	device    *device.Device
	discovery *pathdiscovery.Discovery
	nat       *pathdiscovery.NATClassifier
	bind      *sharedBind
	datagrams *controlDatagramMux
}

func (f *officialWireGuardFactory) setRelayCredentials(credentials *relayCredentials) {
	f.credentials = credentials
}

func (f *officialWireGuardFactory) setLogger(logger *slog.Logger) {
	f.logger = logger
}

func newWireGuardFactory() (wireGuardFactory, error) {
	return &officialWireGuardFactory{generations: &socketGenerationSource{}}, nil
}

func (f *officialWireGuardFactory) New(
	ctx context.Context,
	tunValue netadmin.TUN,
	filter *policyFilter,
	observer PacketObserver,
	relayConfig *relay.Config,
) (wireGuardDevice, error) {
	if f == nil || f.generations == nil {
		return nil, errors.New("dataplane: wireguard factory is not initialized")
	}
	tunDevice, err := acquireTUN(tunValue, f.logger)
	if err != nil {
		return nil, err
	}
	if filter != nil || observer != nil {
		tunDevice = &observedTUN{
			Device:   tunDevice,
			filter:   filter,
			observer: observer,
		}
	}
	logger := newDeviceLogger(f.logger, time.Now)
	var relayPool *relay.Pool
	if relayConfig != nil {
		if !usesInterchange(*relayConfig) || f.credentials == nil {
			_ = tunDevice.Close()

			return nil, errors.New("dataplane: relay configuration names no Interchange relay")
		}
		relayPool, err = relay.New(ctx, *relayConfig, interchange.NewDialer(f.credentials))
		if err != nil {
			_ = tunDevice.Close()

			return nil, err
		}
	}
	bind, err := newSharedBindWithRelay(
		conn.NewDefaultBind(),
		f.generations,
		relayPool,
	)
	if err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}
	discovery, err := pathdiscovery.NewDiscovery(bind)
	if err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}
	natClassifier, err := pathdiscovery.NewNATClassifier(
		bind,
		netcheck.Config{},
	)
	if err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}
	// Endpoint discovery and NAT classification both use STUN on the shared
	// socket; each ignores answers to transactions it did not send.
	datagrams, err := newControlDatagramMux(pathdiscovery.JoinHandlers(discovery, natClassifier))
	if err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}
	if err := bind.setDatagramHandler(datagrams); err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}

	return &officialWireGuardDevice{
		device:    newEndpointAuthorityDevice(tunDevice, bind, logger),
		discovery: discovery,
		nat:       natClassifier,
		bind:      bind,
		datagrams: datagrams,
	}, nil
}

func (d *officialWireGuardDevice) Configure(configuration io.Reader) error {
	return configureWithEndpointAuthority(d.device, configuration)
}

func (d *officialWireGuardDevice) Up() error { return d.device.Up() }

// Done is closed once the device has closed, by Close or on its own.
func (d *officialWireGuardDevice) Done() <-chan struct{} { return d.device.Wait() }

// PeerTraffic reads the device's cumulative per-peer counters.
func (d *officialWireGuardDevice) PeerTraffic() (map[[32]byte]peerTraffic, error) {
	response, err := d.device.IpcGet()
	if err != nil {
		return nil, err
	}
	return parsePeerTraffic(response), nil
}

func (d *officialWireGuardDevice) Close() {
	d.device.Close()
	_ = d.bind.closeRelayPermanently()
}

func (d *officialWireGuardDevice) DiscoverySocket() pathdiscovery.Socket {
	if d == nil || d.discovery == nil {
		return pathdiscovery.Socket{}
	}

	return d.discovery.Socket()
}

func (d *officialWireGuardDevice) DiscoverEndpoints(
	ctx context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	if d == nil || d.discovery == nil {
		return pathdiscovery.DiscoveryResult{}, pathdiscovery.ErrTransportClosed
	}

	return d.discovery.Discover(ctx, scope, servers)
}

func (d *officialWireGuardDevice) ClassifyNAT(
	ctx context.Context,
	servers []netip.AddrPort,
	local []netip.AddrPort,
) (pathdiscovery.NATReport, error) {
	if d == nil || d.nat == nil {
		return pathdiscovery.NATReport{}, pathdiscovery.ErrTransportClosed
	}

	return d.nat.Classify(ctx, servers, local)
}

func (d *officialWireGuardDevice) Socket() pathdiscovery.Socket {
	if d == nil || d.bind == nil {
		return pathdiscovery.Socket{}
	}

	return d.bind.Socket()
}

func (d *officialWireGuardDevice) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	if d == nil || d.bind == nil {
		return pathdiscovery.Socket{}, pathdiscovery.ErrTransportClosed
	}

	return d.bind.SendDatagram(packet, destination)
}

func (d *officialWireGuardDevice) SendRelayDatagram(packet []byte, peerNode [32]byte) error {
	if d == nil || d.bind == nil {
		return pathdiscovery.ErrTransportClosed
	}

	return d.bind.SendRelayDatagram(packet, peerNode)
}

func (d *officialWireGuardDevice) SetPeerProbeHandler(
	handler pathdiscovery.DatagramHandler,
) {
	if d == nil || d.datagrams == nil {
		return
	}
	d.datagrams.setPeerHandler(handler)
}

func (d *officialWireGuardDevice) RelayHealth() relay.HealthSnapshot {
	if d == nil || d.bind == nil {
		return relay.HealthSnapshot{}
	}

	return d.bind.RelayHealth()
}

// SetRelayFailureHook forwards relay connection failures to hook.
func (d *officialWireGuardDevice) SetRelayFailureHook(hook func()) {
	if d == nil || d.bind == nil {
		return
	}
	d.bind.SetRelayFailureHook(hook)
}

func (d *officialWireGuardDevice) PrepareRelayRegion(regionID int) error {
	if d == nil || d.bind == nil {
		return pathdiscovery.ErrTransportClosed
	}

	return d.bind.PrepareRelayRegion(regionID)
}

func (d *officialWireGuardDevice) ReplaceRelayAuthority(homeRegion int, peers []relay.Peer) error {
	if d == nil || d.bind == nil {
		return pathdiscovery.ErrTransportClosed
	}

	return d.bind.ReplaceRelayAuthority(homeRegion, peers)
}
