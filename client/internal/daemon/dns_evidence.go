package daemon

import (
	"context"
	"math/rand/v2"
	"net/url"
	"slices"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/dnsdigest"
)

// DNS evidence (DNS design D1b §8): what the host applied, as the DNS digest
// of the map's DNS routes and search domains, reported with the packet
// filter's digest in EnforcementReport; or why it applies none.

// Reasons the host applies no DNS (mtcp-v1 §8.4).
const (
	dnsReasonUserOff     = "user_off"
	dnsReasonApplyFailed = "apply_failed"
)

// dnsEvidence is the DNS the host last applied; known is false before any
// apply, or when its digest cannot be computed.
type dnsEvidence struct {
	known  bool
	digest dnsdigest.Digest
	routes int
	reason string
}

// dnsUserChoice is a DNS controller the person can turn off on the Device
// (Android): it applies none of the map's DNS then.
type dnsUserChoice interface {
	UsesMeshDNS() bool
}

// dnsInfrastructureController is a DNS controller whose root zone leaves
// MeshTransit's own infrastructure to the network (DNS design D1b §5.8).
type dnsInfrastructureController interface {
	SetInfrastructureNames([]string)
}

// dnsReapplier is a DNS controller that applies the last map again on a
// change of its own (Android: the person turns MeshTransit DNS off or on)
// and reports what came of it.
type dnsReapplier interface {
	OnReapply(func(snapshot networkmap.Snapshot, err error))
}

// reappliedDNS records the evidence of a DNS controller applying the last
// map again, as applyMapDNS does for a map (DNS design D1b Q7).
func (s *Service) reappliedDNS(snapshot networkmap.Snapshot, err error) {
	if err != nil {
		s.recordDNSEvidence(dnsEvidence{known: true, reason: dnsReasonApplyFailed})
		return
	}
	s.recordDNSEvidence(s.appliedDNSEvidence(snapshot))
}

// appliedDNSEvidence is the evidence of applying snapshot's DNS: its digest,
// or user_off when the person turned DNS off.
func (s *Service) appliedDNSEvidence(snapshot networkmap.Snapshot) dnsEvidence {
	if choice, ok := s.dns.(dnsUserChoice); ok && !choice.UsesMeshDNS() {
		return dnsEvidence{known: true, reason: dnsReasonUserOff}
	}
	digest, routes, err := digestDNS(snapshot.DNS)
	if err != nil {
		return dnsEvidence{}
	}
	return dnsEvidence{known: true, digest: digest, routes: routes}
}

// digestDNS computes the DNS digest v1 of a map's DNS configuration, as the
// node kept it after validating the map; none is the empty configuration.
func digestDNS(config *networkmap.DNSConfig) (dnsdigest.Digest, int, error) {
	if config == nil {
		return dnsdigest.Compute(nil, nil)
	}
	routes := make([]dnsdigest.Route, 0, len(config.Routes))
	for _, route := range config.Routes {
		digested := dnsdigest.Route{Suffix: route.Suffix, Unavailable: route.Unavailable, FailOpen: route.FailOpen}
		for _, resolver := range route.Resolvers {
			digested.Resolvers = append(digested.Resolvers,
				dnsdigest.Resolver{Address: resolver.Address.Addr(), Port: resolver.Address.Port()})
		}
		routes = append(routes, digested)
	}
	return dnsdigest.Compute(routes, config.SearchDomains)
}

// recordDNSEvidence keeps evidence and hands it to Core with the packet
// filter's digest at once.
func (s *Service) recordDNSEvidence(evidence dnsEvidence) {
	s.dnsEvidenceMu.Lock()
	changed := s.dnsEvidence != evidence
	s.dnsEvidence = evidence
	republish := s.dnsRepublish
	s.dnsEvidenceMu.Unlock()
	if changed && republish != nil {
		republish()
	}
}

// currentDNSEvidence returns the DNS evidence last recorded.
func (s *Service) currentDNSEvidence() dnsEvidence {
	s.dnsEvidenceMu.Lock()
	defer s.dnsEvidenceMu.Unlock()
	return s.dnsEvidence
}

// setDNSRepublish sets how the session hands new DNS evidence to Core; nil
// when no session reports.
func (s *Service) setDNSRepublish(republish func()) {
	s.dnsEvidenceMu.Lock()
	defer s.dnsEvidenceMu.Unlock()
	s.dnsRepublish = republish
}

// withDNSEvidence adds the DNS evidence to an enforcement report.
func withDNSEvidence(report controlplane.EnforcementReport, evidence dnsEvidence) controlplane.EnforcementReport {
	if !evidence.known {
		return report
	}
	report.DNSKnown, report.DNSDigest, report.DNSRoutes, report.DNSReason = true, evidence.digest, evidence.routes,
		evidence.reason
	return report
}

// infrastructureNames are the names of MeshTransit's own infrastructure a
// root zone leaves to the network: the control host and the relays' hosts.
func infrastructureNames(controlURL string, snapshot networkmap.Snapshot) []string {
	var names []string
	if parsed, err := url.Parse(controlURL); err == nil && parsed.Hostname() != "" {
		names = append(names, parsed.Hostname())
	}
	for _, region := range snapshot.Relays {
		for _, node := range region.Nodes {
			if node.HostName != "" && !slices.Contains(names, node.HostName) {
				names = append(names, node.HostName)
			}
		}
	}
	return names
}

// dnsHealthController is a DNS controller whose resolver measures its zones'
// resolvers.
type dnsHealthController interface {
	ResolverHealth() ([]controlplane.ResolverHealth, bool)
}

// Resolver health is read every dnsHealthInterval plus up to dnsHealthJitter,
// so the Devices a shared resolver serves do not all report at once.
const (
	dnsHealthInterval = 30 * time.Second
	dnsHealthJitter   = 10 * time.Second
)

// publishDNSHealth hands the resolver's health to the map session until ctx
// ends; the session sends it on change and every 5 minutes.
func publishDNSHealth(ctx context.Context, measured dnsHealthController, updates chan []controlplane.ResolverHealth) {
	timer := time.NewTimer(dnsHealthInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if health, ok := measured.ResolverHealth(); ok {
			offerLatest(updates, health)
		}
		timer.Reset(dnsHealthInterval + rand.N(dnsHealthJitter)) //nolint:gosec // G404: spacing, not a secret
	}
}

// The desktop DNS controller reports resolver health and leaves the
// infrastructure's names to the network.
var (
	_ dnsHealthController         = (*dnsconfig.Manager)(nil)
	_ dnsInfrastructureController = (*dnsconfig.Manager)(nil)
)
