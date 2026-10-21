package dataplane

import (
	"net/netip"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/shared/internet"
)

// exitConsumerIdle is how long a consumer counts against the exit node's
// consumer limit after its last packet.
const exitConsumerIdle = 10 * time.Minute

// exitFilter is the exit node's part of the packet filter (exit node design
// §4.3, layer 1): the pool's rules, admitted only to the Internet and never
// to the exit node's own addresses or the Sites it serves, for at most
// maxConsumers consumers. Its zero value admits nothing.
type exitFilter struct {
	active       bool
	rules        []compiledRule
	local        map[netip.Addr]struct{}
	maxConsumers int
	consumers    map[netip.Addr]time.Time
}

// SetExitInstalled records how the helper forwards as an exit node: rules is
// the served pool's rules, local the exit node's own addresses outside the
// mesh, maxConsumers its consumer limit. Without rules it forwards nothing.
func (f *policyFilter) SetExitInstalled(rules []networkmap.Rule, local []netip.Addr, maxConsumers int) {
	if f == nil {
		return
	}
	exit := exitFilter{}
	if len(rules) != 0 && maxConsumers > 0 {
		exit = exitFilter{
			active: true, local: map[netip.Addr]struct{}{}, maxConsumers: maxConsumers,
			consumers: map[netip.Addr]time.Time{},
		}
		for _, rule := range rules {
			exit.rules = append(exit.rules, compiledRule{
				sources:      append([]networkmap.Selector{}, rule.Sources...),
				destinations: append([]networkmap.Destination{}, rule.Destinations...),
				protocols:    append([]uint8{}, rule.Protocols...),
			})
		}
		for _, address := range local {
			exit.local[address.Unmap()] = struct{}{}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if exit.active && f.exit.active {
		exit.consumers = f.exit.consumers
	}
	f.exit = exit
}

// internetLocked reports whether address is on the Internet as the exit
// node sees it: in the shared Internet set, and neither one of its own
// addresses nor in a Site it serves.
func (f *policyFilter) internetLocked(address netip.Addr) bool {
	if _, own := f.exit.local[address]; own {
		return false
	}
	return internet.Contains(address) && !f.served.contains(address)
}

// exitInboundLocked admits a consumer's packet to the Internet as the pool's
// rules allow; the kernel subtracts what it learned locally again and
// tracks the connection from there.
func (f *policyFilter) exitInboundLocked(header packetmeta.Header, now time.Time) bool {
	if !f.exit.active || !f.internetLocked(header.Destination) || !f.peerUsableAt(header.Source, now) ||
		!rulesAllow(f.exit.rules, header) {
		return false
	}
	return f.exit.admitConsumer(header.Source, now)
}

// exitOutboundLocked admits the Internet's answers to a consumer: the
// kernel lets only answers through (layer 2). "Fragmentation needed" (and
// IPv6's "packet too big") about a packet the consumer sent to the Internet
// passes from whatever hop sent it, a private or CGNAT router on the path
// included: without it path MTU discovery fails. Other errors from such a
// hop do not, so a traceroute never shows the exit network's own routers.
// The kernel admits it only as related to the consumer's connection.
func (f *policyFilter) exitOutboundLocked(header packetmeta.Header, packet []byte, now time.Time) bool {
	if !f.exit.active || !f.peerUsableAt(header.Destination, now) {
		return false
	}
	if f.internetLocked(header.Source) {
		return true
	}
	tooBig := (header.Protocol == packetmeta.ProtocolICMPv4 && header.ICMPType == 3 && header.ICMPCode == 4) ||
		(header.Protocol == packetmeta.ProtocolICMPv6 && header.ICMPType == 2)
	if !tooBig {
		return false
	}
	quoted, ok := packetmeta.ICMPErrorQuote(packet)
	return ok && quoted.Source.Unmap() == header.Destination && f.internetLocked(quoted.Destination.Unmap())
}

// exitDNSLocked admits a consumer's DNS question to the exit node's own
// address, port 53: the forwarder answers every source a rule of the pool
// names, whatever ports the rule opens (exit node design §7.2). Its answer
// leaves as any reply of this node.
func (f *policyFilter) exitDNSLocked(header packetmeta.Header, now time.Time) bool {
	if !f.exit.active || header.DestinationPort != 53 ||
		(header.Protocol != packetmeta.ProtocolUDP && header.Protocol != packetmeta.ProtocolTCP) ||
		!f.peerUsableAt(header.Source, now) {
		return false
	}
	named := false
	for _, rule := range f.exit.rules {
		if selectorsContain(rule.sources, header.Source) {
			named = true
			break
		}
	}
	return named && f.exit.admitConsumer(header.Source, now)
}

// admitConsumer counts consumer against the limit: a known one always, a new
// one while fewer than maxConsumers were active within exitConsumerIdle.
func (exit *exitFilter) admitConsumer(consumer netip.Addr, now time.Time) bool {
	if _, known := exit.consumers[consumer]; !known && len(exit.consumers) >= exit.maxConsumers {
		for address, seen := range exit.consumers {
			if now.Sub(seen) > exitConsumerIdle {
				delete(exit.consumers, address)
			}
		}
		if len(exit.consumers) >= exit.maxConsumers {
			return false
		}
	}
	exit.consumers[consumer] = now
	return true
}
