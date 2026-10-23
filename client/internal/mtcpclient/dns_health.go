package mtcpclient

import (
	"slices"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	// dnsHealthHeartbeat is how often unchanged resolver health is sent
	// again (mtcp-v1 §8.6).
	dnsHealthHeartbeat = 5 * time.Minute
	// dnsHealthSpacing is the least time between two reports: Core drops a
	// report sooner than 20 s after the last (mtcp-v1 §8.6).
	dnsHealthSpacing = 30 * time.Second
	// maximumDNSHealth bounds one report (mtcp-v1 §8.6).
	maximumDNSHealth = 64
)

var resolverStates = map[controlplane.ResolverState]mtcpv1.ResolverHealth_State{
	controlplane.ResolverOK:       mtcpv1.ResolverHealth_OK,
	controlplane.ResolverBroken:   mtcpv1.ResolverHealth_BROKEN,
	controlplane.ResolverStopped:  mtcpv1.ResolverHealth_STOPPED,
	controlplane.ResolverRefusing: mtcpv1.ResolverHealth_REFUSING,
	controlplane.ResolverIdle:     mtcpv1.ResolverHealth_IDLE,
}

// sendDNSHealth sends how the node's resolver sees the zones' resolvers
// when Core takes it (dns.root1): on change, at least dnsHealthSpacing
// apart, and every dnsHealthHeartbeat while unchanged.
func (run *sessionRun) sendDNSHealth() error {
	if !run.mapped || !run.stream.options.EnableDNSForward || !run.supports("dns.root1") {
		return nil
	}
	health := run.stream.reports.resolverHealth()
	if health == nil {
		return nil
	}
	health = health[:min(len(health), maximumDNSHealth)]
	if !run.dnsHealthDue(health) {
		return nil
	}
	report := &mtcpv1.DnsHealthReport{Resolvers: make([]*mtcpv1.ResolverHealth, 0, len(health))}
	for _, resolver := range health {
		state, known := resolverStates[resolver.State]
		if !known || !resolver.Resolver.IsValid() {
			continue
		}
		reported := &mtcpv1.ResolverHealth{Ip: resolver.Resolver.Addr().AsSlice(), State: state}
		if port := resolver.Resolver.Port(); port != 53 {
			reported.Port = uint32(port)
		}
		if !resolver.LastOK.IsZero() {
			reported.LastOkMs = resolver.LastOK.UnixMilli()
		}
		report.Resolvers = append(report.Resolvers, reported)
	}
	if err := run.send(sharedmtcp.MessageDNSHealthReport, report); err != nil {
		return err
	}
	// Never nil once sent: a later report keeps the spacing.
	run.dnsHealthSent, run.dnsHealthSentAt = append([]controlplane.ResolverHealth{}, health...), time.Now()
	return nil
}

// dnsHealthDue reports whether health is to be sent now: the first of the
// session, a change of state at least dnsHealthSpacing after the last, or
// anything at the heartbeat; an empty report only after one that was not.
// A resolver's last answer moving on is no change of state.
func (run *sessionRun) dnsHealthDue(health []controlplane.ResolverHealth) bool {
	// No resolvers to report, and none reported: nothing for Core to store.
	if len(health) == 0 && len(run.dnsHealthSent) == 0 {
		return false
	}
	if run.dnsHealthSent == nil {
		return true
	}
	since := time.Since(run.dnsHealthSentAt)
	changed := !slices.EqualFunc(run.dnsHealthSent, health, func(sent, now controlplane.ResolverHealth) bool {
		return sent.Resolver == now.Resolver && sent.State == now.State
	})
	return since >= dnsHealthHeartbeat || (changed && since >= dnsHealthSpacing)
}
