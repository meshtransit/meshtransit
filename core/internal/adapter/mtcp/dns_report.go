package mtcp

import (
	"context"
	"net/netip"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/dnsdigest"
)

// DNS evidence of a node that declared dns.root1 (DNS design D1b §8, §9).

const (
	// dnsHealthInterval spaces the resolver health reports taken from one
	// session: a node reports at least 30 s apart (mtcp-v1 §8.6), so a
	// sooner one is dropped and the node's next one counts.
	dnsHealthInterval = 20 * time.Second
	dnsHealthTimeout  = 5 * time.Second
	dnsDefaultPort    = 53
)

// DNSHealthStreams stores how a node's resolver sees the zones' resolvers
// (mtcp-v1 §8.6); the map stream service implements it when its recorder
// can.
type DNSHealthStreams interface {
	ReportDNSHealth(ctx context.Context, machine control.AuthenticatedMachine, nodeKey node.Key,
		resolvers []mapsession.ResolverHealth) error
}

var resolverHealthStates = map[mtcpv1.ResolverHealth_State]mapsession.ResolverState{
	mtcpv1.ResolverHealth_OK:       mapsession.ResolverOK,
	mtcpv1.ResolverHealth_BROKEN:   mapsession.ResolverBroken,
	mtcpv1.ResolverHealth_STOPPED:  mapsession.ResolverStopped,
	mtcpv1.ResolverHealth_REFUSING: mapsession.ResolverRefusing,
	mtcpv1.ResolverHealth_IDLE:     mapsession.ResolverIdle,
}

// digestDNSConfig computes the DNS digest v1 of a DNS configuration
// (docs/protocol/dns-digest-v1.md).
func digestDNSConfig(config *mtcpv1.DnsConfig) (mapsession.DNSDigest, error) {
	routes := make([]dnsdigest.Route, 0, len(config.GetRoutes()))
	for _, route := range config.GetRoutes() {
		digested := dnsdigest.Route{Suffix: route.GetSuffix(), Unavailable: route.GetUnavailable(),
			FailOpen: route.GetFailOpen()}
		for _, resolver := range route.GetResolvers() {
			address, ok := netip.AddrFromSlice(resolver.GetIp())
			if !ok {
				return mapsession.DNSDigest{}, ErrMapEncoding
			}
			digested.Resolvers = append(digested.Resolvers,
				dnsdigest.Resolver{Address: address, Port: uint16(resolver.GetPort())}) //nolint:gosec // G115: a port the map encodes
		}
		routes = append(routes, digested)
	}
	digest, count, err := dnsdigest.Compute(routes, config.GetSearchDomains())
	if err != nil {
		return mapsession.DNSDigest{}, err
	}
	return mapsession.NewDNSDigest(digest, count)
}

// suffixesOf returns the suffix of each route of a DNS configuration.
func suffixesOf(config *mtcpv1.DnsConfig) []string {
	suffixes := make([]string, 0, len(config.GetRoutes()))
	for _, route := range config.GetRoutes() {
		suffixes = append(suffixes, route.GetSuffix())
	}
	return suffixes
}

// resolversOf returns each resolver of a DNS configuration as an address
// and port, 0 being 53.
func resolversOf(config *mtcpv1.DnsConfig) map[netip.AddrPort]struct{} {
	resolvers := make(map[netip.AddrPort]struct{})
	for _, route := range config.GetRoutes() {
		for _, resolver := range route.GetResolvers() {
			if address, port, ok := resolverAddress(resolver.GetIp(), resolver.GetPort()); ok {
				resolvers[netip.AddrPortFrom(address, port)] = struct{}{}
			}
		}
	}
	return resolvers
}

// resolverAddress reads an address of 4 or 16 bytes and a port, 0 being 53.
func resolverAddress(ip []byte, port uint32) (netip.Addr, uint16, bool) {
	address, ok := netip.AddrFromSlice(ip)
	if !ok || (len(ip) != 4 && len(ip) != 16) || port > 65535 {
		return netip.Addr{}, 0, false
	}
	if port == 0 {
		port = dnsDefaultPort
	}
	return address.Unmap(), uint16(port), true
}

// dnsEvidence reads the DNS part of an EnforcementReport from a node that
// declared dns.root1: a digest, or none with a known reason. Anything else
// is left out; the policy evidence still counts.
func (conversation *conversation) dnsEvidence(report *mtcpv1.EnforcementReport) (mapsession.DNSDigest, string) {
	if !conversation.dnsRoot.Load() {
		return mapsession.DNSDigest{}, ""
	}
	if len(report.GetDnsDigest()) == len(dnsdigest.Digest{}) {
		var raw dnsdigest.Digest
		copy(raw[:], report.GetDnsDigest())
		if digest, err := mapsession.NewDNSDigest(raw, int(report.GetDnsRoutes())); err == nil {
			return digest, ""
		}
		return mapsession.DNSDigest{}, ""
	}
	switch reason := report.GetDnsReason(); reason {
	case mapsession.DNSUserOff, mapsession.DNSApplyFailed:
		return mapsession.DNSDigest{}, reason
	default:
		return mapsession.DNSDigest{}, ""
	}
}

// dnsHealth validates a DnsHealthReport and stores the resolvers the
// session was sent. A report sooner than dnsHealthInterval after the last is
// dropped; the node reports again on change or within 5 minutes.
func (conversation *conversation) dnsHealth(ctx context.Context, report *mtcpv1.DnsHealthReport) error {
	if !conversation.session.Supports("dns.root1") {
		return Violation(mtcpv1.Error_INVALID, "dns health report without dns.root1")
	}
	if len(report.GetResolvers()) > mapsession.MaximumResolverHealth {
		return Violation(mtcpv1.Error_INVALID, "invalid dns health report")
	}
	resolvers := make([]mapsession.ResolverHealth, 0, len(report.GetResolvers()))
	for _, reported := range report.GetResolvers() {
		state, known := resolverHealthStates[reported.GetState()]
		address, port, valid := resolverAddress(reported.GetIp(), reported.GetPort())
		if !known || !valid || reported.GetLastOkMs() < 0 {
			return Violation(mtcpv1.Error_INVALID, "invalid resolver health")
		}
		health := mapsession.ResolverHealth{Resolver: netip.AddrPortFrom(address, port), State: state}
		if reported.GetLastOkMs() > 0 {
			health.LastOK = time.UnixMilli(reported.GetLastOkMs()).UTC()
		}
		resolvers = append(resolvers, health)
	}
	if !mapsession.ValidResolverHealth(resolvers) {
		return Violation(mtcpv1.Error_INVALID, "invalid dns health report")
	}
	// A node that declared dns.root1 without what it needs (dns.forward1,
	// dns.split, map.large1) is sent no root zone and reports nothing Core
	// keeps.
	streams, ok := conversation.application.options.Streams.(DNSHealthStreams)
	now := conversation.application.now()
	if !conversation.dnsRoot.Load() {
		return nil
	}
	if !ok || now.Sub(conversation.lastDNSHealth) < dnsHealthInterval {
		if ok {
			conversation.application.options.Metrics.limited(limitDNSHealth)
		}
		return nil
	}
	sent, mapped := conversation.sink.sentResolvers()
	if !mapped {
		return nil // no map yet; the node reports again
	}
	kept := resolvers[:0]
	for _, health := range resolvers {
		if _, found := sent[health.Resolver]; found {
			kept = append(kept, health)
		}
	}
	conversation.lastDNSHealth = now
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		return nil
	}
	recordCtx, cancel := context.WithTimeout(ctx, dnsHealthTimeout)
	defer cancel()
	if err := streams.ReportDNSHealth(recordCtx, machine, conversation.currentKey(), kept); err != nil {
		conversation.application.options.Logger.DebugContext(ctx, "mtcp dns health not stored", "error", err)
	}
	return nil
}
