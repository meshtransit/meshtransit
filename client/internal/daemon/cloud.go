package daemon

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/cloudaddr"
	"meshtransit.net/client/internal/pathdiscovery"
)

// CloudOff is the cloud address state when lookups are turned off
// (--cloud-metadata=off) or the packet engine is not running.
const CloudOff = "off"

// CloudAddresses keeps the instance's public cloud addresses current.
// *cloudaddr.Watcher implements it.
type CloudAddresses interface {
	Run(ctx context.Context)
	Addresses() []netip.Addr
	Changes() <-chan struct{}
	NetworkChanged()
	Status() cloudaddr.Status
}

// CloudStatus is the daemon's view of the instance's cloud addresses.
// Addresses are shown locally on explicit request only; they are never logged.
type CloudStatus struct {
	State      string
	Platform   string
	Addresses  []netip.Addr
	ObservedAt time.Time
	Error      string
}

func (s *Service) cloudStatus() CloudStatus {
	if s == nil || s.cloud == nil {
		return CloudStatus{State: CloudOff}
	}
	status := s.cloud.Status()

	return CloudStatus{
		State:      status.State,
		Platform:   string(status.Platform),
		Addresses:  slices.Clone(status.Addresses),
		ObservedAt: status.ObservedAt,
		Error:      status.Error,
	}
}

// startCloudAddresses runs the cloud address watcher for one endpoint
// refresh session. It returns the watcher's change signal (nil without a
// watcher) and a stop function that waits for it.
func (s *Service) startCloudAddresses(ctx context.Context) (<-chan struct{}, func()) {
	if s.cloud == nil {
		return nil, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.cloud.Run(ctx)
	}()

	return s.cloud.Changes(), func() {
		cancel()
		<-done
	}
}

// cloudCandidates returns the cloud public addresses on port as static
// candidates: a cloud public IPv4 address is a 1:1 NAT that keeps the port,
// and a cloud IPv6 address is the interface's own.
func (s *Service) cloudCandidates(port uint16) pathdiscovery.Set {
	if s.cloud == nil || port == 0 {
		return pathdiscovery.Set{}
	}
	var candidates []pathdiscovery.Candidate
	for _, addr := range s.cloud.Addresses() {
		candidate, err := pathdiscovery.NewCandidate(netip.AddrPortFrom(addr, port), pathdiscovery.SourceConfigured)
		if err == nil {
			candidates = append(candidates, candidate)
		}
	}
	set, err := pathdiscovery.NewSet(candidates)
	if err != nil {
		return pathdiscovery.Set{}
	}

	return set
}
