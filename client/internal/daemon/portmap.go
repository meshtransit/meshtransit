package daemon

import (
	"context"
	"net/netip"
	"time"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/portmap"
)

// PortMappingOff is the port mapping state when it is turned off
// (--port-mapping=off) or the packet engine is not running.
const PortMappingOff = "off"

// PortMapper keeps the WireGuard port mapped on the local gateway.
// *portmap.Mapper implements it.
type PortMapper interface {
	SetPort(port uint16)
	NetworkChanged()
	Changes() <-chan struct{}
	Candidate() (netip.AddrPort, bool)
	Status() portmap.Status
	Run(ctx context.Context)
}

// PortMappingStatus is the daemon's port mapping state. External is shown
// locally on explicit request only; it is never logged.
type PortMappingStatus struct {
	State     string
	Protocol  string
	External  netip.AddrPort
	ExpiresAt time.Time
	Error     string
}

func (s *Service) portMappingStatus() PortMappingStatus {
	if s == nil || s.portMapper == nil {
		return PortMappingStatus{State: PortMappingOff}
	}
	status := s.portMapper.Status()

	return PortMappingStatus{
		State:     status.State,
		Protocol:  string(status.Protocol),
		External:  status.External,
		ExpiresAt: status.ExpiresAt,
		Error:     status.Error,
	}
}

// startPortMapping runs the port mapper for one endpoint refresh session.
// It returns the mapper's change signal (nil without a mapper) and a stop
// function that ends the session's mapper and waits for it to remove the
// mapping.
func (s *Service) startPortMapping(ctx context.Context) (<-chan struct{}, func()) {
	if s.portMapper == nil {
		return nil, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.portMapper.Run(ctx)
	}()

	return s.portMapper.Changes(), func() {
		cancel()
		<-done
	}
}

// localCandidates returns the configured endpoints and the port mapping's
// external endpoint, which discovery cannot observe itself. The mapping is
// offered only when its external address is one meshd observed itself (a
// server-reflexive candidate in observed, or the NAT classification's public
// endpoint): mapping replies are unauthenticated, so a host on the LAN must
// not be able to choose an endpoint peers will probe.
func (s *Service) localCandidates(observed pathdiscovery.Set) (pathdiscovery.Set, error) {
	if s.portMapper == nil {
		return s.configuredCandidates, nil
	}
	external, ok := s.portMapper.Candidate()
	if !ok || !s.observedPublicAddress(external.Addr(), observed) {
		return s.configuredCandidates, nil
	}
	mapped, err := pathdiscovery.NewCandidate(external, pathdiscovery.SourcePortMapping)
	if err != nil {
		return s.configuredCandidates, nil //nolint:nilerr // an unusable mapping is simply not offered
	}
	set, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{mapped})
	if err != nil {
		return s.configuredCandidates, nil //nolint:nilerr // see above
	}

	return pathdiscovery.Merge(s.configuredCandidates, set)
}

func (s *Service) observedPublicAddress(addr netip.Addr, observed pathdiscovery.Set) bool {
	for _, candidate := range observed.Candidates() {
		if candidate.Source() == pathdiscovery.SourceServerReflexive && candidate.Endpoint().Addr() == addr {
			return true
		}
	}
	if s.nat == nil {
		return false
	}
	status := s.nat.get()

	return status.State == NATReady && status.PublicEndpoint.Addr() == addr
}
