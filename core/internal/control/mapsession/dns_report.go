package mapsession

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/dnsdigest"
)

// DNS evidence of a node that declared dns.root1 (DNS design D1b §8, §9):
// the DNS digest of what it was sent and of what it applied, and how its
// resolver sees the zones' resolvers.

// ErrInvalidDNSHealth reports a malformed resolver health report.
var ErrInvalidDNSHealth = errors.New("map session: invalid dns health report")

// Reasons a node applies no DNS (EnforcementReport.dns_reason).
const (
	// DNSUserOff: the person turned MeshTransit DNS off on the Device.
	DNSUserOff = "user_off"
	// DNSApplyFailed: the host refused the DNS configuration.
	DNSApplyFailed = "apply_failed"
)

// MaximumResolverHealth bounds one DNS health report (mtcp-v1 §8.6).
const MaximumResolverHealth = 64

// DNSDigest is the DNS digest v1 of a node's DNS routes and search domains
// (docs/protocol/dns-digest-v1.md) and how many routes it covers.
type DNSDigest struct {
	digest dnsdigest.Digest
	routes int
}

// NewDNSDigest validates a computed DNS digest.
func NewDNSDigest(digest dnsdigest.Digest, routes int) (DNSDigest, error) {
	if digest.IsZero() || routes < 0 || routes > dnsdigest.MaximumRoutes {
		return DNSDigest{}, ErrInvalidEnforcementReport
	}
	return DNSDigest{digest: digest, routes: routes}, nil
}

// Digest returns the digest value.
func (digest DNSDigest) Digest() dnsdigest.Digest { return digest.digest }

// Routes returns how many routes the digest covers.
func (digest DNSDigest) Routes() int { return digest.routes }

// IsValid reports a computed digest.
func (digest DNSDigest) IsValid() bool { return !digest.digest.IsZero() }

// DNSDigestSink is a stream sink that knows the DNS digest of the DNS
// configuration the node holds, for a session that reports what it applied
// (dns.root1); the zero value otherwise. The sink computes it from the
// configuration it sent, so the record is what Core last sent.
type DNSDigestSink interface {
	SentDNSDigest() DNSDigest
}

// sentDNSDigest returns the DNS digest sink reports, or the zero value.
func sentDNSDigest(sink StreamSink) DNSDigest {
	if digested, ok := sink.(DNSDigestSink); ok {
		return digested.SentDNSDigest()
	}
	return DNSDigest{}
}

// validDNSEvidence reports a DNS digest with no reason, or no digest with
// none or a known reason.
func validDNSEvidence(digest DNSDigest, reason string) bool {
	if digest.IsValid() {
		return reason == ""
	}
	return reason == "" || reason == DNSUserOff || reason == DNSApplyFailed
}

// ResolverState is how a node's resolver sees one resolver (mtcp-v1 §8.6).
type ResolverState int

// The states of mtcp-v1 §8.6.
const (
	ResolverOK ResolverState = iota + 1
	ResolverBroken
	ResolverStopped
	ResolverRefusing
	ResolverIdle
)

// ResolverHealth is one resolver of the zones a node applies, as its
// resolver sees it.
type ResolverHealth struct {
	Resolver netip.AddrPort
	State    ResolverState
	// LastOK is its last answer; zero: none since the zones were applied.
	LastOK time.Time
}

// ValidResolverHealth reports at most MaximumResolverHealth resolvers, each
// listed once with a valid address, a port and a known state.
func ValidResolverHealth(resolvers []ResolverHealth) bool {
	if len(resolvers) > MaximumResolverHealth {
		return false
	}
	for index, health := range resolvers {
		if !health.Resolver.IsValid() || health.Resolver.Port() == 0 || health.Resolver.Addr().Zone() != "" ||
			health.State < ResolverOK || health.State > ResolverIdle ||
			slices.ContainsFunc(resolvers[:index], func(other ResolverHealth) bool {
				return other.Resolver == health.Resolver
			}) {
			return false
		}
	}
	return true
}

// DNSHealth is one resolver health report, bound to the authenticated node
// that sent it; the recorder ties it to that node's current map session.
type DNSHealth struct {
	NodeKey            node.Key
	MachineFingerprint [32]byte
	Resolvers          []ResolverHealth
	ReportedAt         time.Time
}

// DNSHealthRecorder stores the latest resolver health of a node's current
// map session. It reports false when the node has no current session or the
// session belongs to another machine.
type DNSHealthRecorder interface {
	RecordDNSHealth(context.Context, DNSHealth) (bool, error)
}

// ReportDNSHealth stores how a node's resolver sees the resolvers of the
// zones it applies (mtcp-v1 §8.6). The resolvers must already be those the
// session was sent; the recorder is the enforcement recorder when it also
// records DNS health.
func (service *StreamService) ReportDNSHealth(ctx context.Context, machine control.AuthenticatedMachine,
	nodeKey node.Key, resolvers []ResolverHealth,
) error {
	if ctx == nil || service == nil || !machine.IsValid() {
		return ErrInvalidStreamService
	}
	recorder, ok := service.enforcement.(DNSHealthRecorder)
	if !ok {
		return ErrEnforcementUnavailable
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil || !ValidResolverHealth(resolvers) {
		return ErrInvalidDNSHealth
	}
	now := time.Now().UTC()
	stored := slices.Clone(resolvers)
	for index := range stored {
		// A clock ahead says nothing more than "now".
		if stored[index].LastOK.After(now) {
			stored[index].LastOK = now
		}
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CoordinationTimeout)
	defer cancel()
	recorded, err := recorder.RecordDNSHealth(operationCtx, DNSHealth{
		NodeKey: identity.NodeKey(), MachineFingerprint: identity.MachineFingerprint(),
		Resolvers: stored, ReportedAt: now,
	})
	if err != nil {
		return errors.Join(ErrEnforcementUnavailable, err)
	}
	if !recorded {
		return ErrNoEnforcementStream
	}
	return nil
}
