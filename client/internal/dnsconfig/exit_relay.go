package dnsconfig

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/shared/internet"
)

// A consumer using an exit node asks a zone's Internet resolver through the
// exit node's forwarder: its question carries the EDNS option
// ednsOptionRelay naming the resolver, and the forwarder relays it when Core
// lists the resolver for the pool (mtcp-v1 §7.7, DNS design D1c).

// ednsOptionRelay is the EDNS option of a relayed question and its answer
// (Local/Experimental Use, RFC 6891).
const ednsOptionRelay = 65432

// relayVersion is the version of the option's data.
const relayVersion = 1

// What became of a relayed question, in the answer's option.
const (
	relayAnswered    = 0 // the resolver answered: its answer as it is
	relayNoAnswer    = 1 // the resolver did not answer
	relayNotAllowed  = 2 // the forwarder does not relay to that resolver
	relayBusy        = 3 // the forwarder is busy
	relayUplinkDown  = 4 // the exit node's own way to the Internet is down
	relayStatusCount = 5
)

const (
	// relayTimeout bounds asking the resolver: shorter than the consumer's
	// attempt, so that it hears the resolver did not answer.
	relayTimeout = time.Second
	// relayTimeoutWindow and relayTimeoutsDown: resolvers that did not answer
	// within the window, beyond which the exit node's own way out is taken as
	// down.
	relayTimeoutWindow = 30 * time.Second
	relayTimeoutsDown  = 2
	// relayStalledAfter and maxStalledRelayQuestions hold back a resolver
	// that keeps not answering, so it cannot take every slot.
	relayStalledAfter        = 3
	maxStalledRelayQuestions = 16
	// relayRetireGrace is how long a resolver Core stopped listing is still
	// relayed to, for the consumers that had it: a consumer's map may carry
	// the zone it belongs to that much longer than the exit node's, through
	// the Network's DNS window and a map refresh (TD-CORE-89).
	relayRetireGrace = 2 * time.Minute
)

// retiredRelay is a resolver Core no longer lists for some consumers,
// relayed to until a deadline: for any consumer until openUntil, when it
// was listed for any, and for each source until its own.
type retiredRelay struct {
	openUntil time.Time
	sources   map[netip.Addr]time.Time
}

var errRelayOption = errors.New("dnsconfig: malformed relay option")

// relayOption returns the resolver a question's EDNS asks to relay to;
// present reports the option, and an option twice or malformed is present
// and not valid.
func relayOption(message dnsmessage.Message) (target netip.AddrPort, present bool, err error) {
	for _, additional := range message.Additionals {
		opt, ok := additional.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, option := range opt.Options {
			if option.Code != ednsOptionRelay {
				continue
			}
			if present {
				return netip.AddrPort{}, true, errRelayOption
			}
			present = true
			target, err = decodeRelayTarget(option.Data)
		}
	}
	return target, present, err
}

func decodeRelayTarget(data []byte) (netip.AddrPort, error) {
	if len(data) < 4 || data[0] != relayVersion {
		return netip.AddrPort{}, errRelayOption
	}
	port := binary.BigEndian.Uint16(data[2:4])
	switch {
	case data[1] == 1 && len(data) == 8:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[4:8])), port), nil
	case data[1] == 2 && len(data) == 20:
		address := netip.AddrFrom16([16]byte(data[4:20]))
		if address.Is4In6() {
			return netip.AddrPort{}, errRelayOption
		}
		return netip.AddrPortFrom(address, port), nil
	default:
		return netip.AddrPort{}, errRelayOption
	}
}

// encodeRelayTarget is the option's data naming target.
func encodeRelayTarget(target netip.AddrPort) []byte {
	address := target.Addr().Unmap()
	family := byte(1)
	if address.Is6() {
		family = 2
	}
	data := []byte{relayVersion, family}
	data = binary.BigEndian.AppendUint16(data, target.Port())
	return append(data, address.AsSlice()...)
}

// withoutRelayOption returns query without the relay option, to ask the
// resolver itself.
func withoutRelayOption(query []byte) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		return nil, err
	}
	for index, additional := range message.Additionals {
		opt, ok := additional.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		options := slices.DeleteFunc(slices.Clone(opt.Options), func(option dnsmessage.Option) bool {
			return option.Code == ednsOptionRelay
		})
		message.Additionals[index].Body = &dnsmessage.OPTResource{Options: options}
	}
	return message.Pack()
}

// withRelayStatus adds the relay option with status to response, when query
// asked to relay; any other response is left as it is.
func withRelayStatus(query, response []byte, status byte) []byte {
	marked, _ := markRelayStatus(query, response, status)
	return marked
}

// markRelayStatus is withRelayStatus that reports whether the status was
// added: response comes back unchanged when it was not.
func markRelayStatus(query, response []byte, status byte) ([]byte, bool) {
	if len(response) == 0 {
		return response, false
	}
	var asked dnsmessage.Message
	if asked.Unpack(query) != nil {
		return response, false
	}
	if _, present, _ := relayOption(asked); !present {
		return response, false
	}
	var message dnsmessage.Message
	if message.Unpack(response) != nil {
		return response, false
	}
	option := dnsmessage.Option{Code: ednsOptionRelay, Data: []byte{relayVersion, status}}
	found := false
	for index, additional := range message.Additionals {
		if opt, ok := additional.Body.(*dnsmessage.OPTResource); ok {
			options := slices.DeleteFunc(slices.Clone(opt.Options), func(existing dnsmessage.Option) bool {
				return existing.Code == ednsOptionRelay
			})
			message.Additionals[index].Body = &dnsmessage.OPTResource{Options: append(options, option)}
			found = true
		}
	}
	if !found {
		header := dnsmessage.ResourceHeader{}
		if header.SetEDNS0(maxUDPSize, dnsmessage.RCodeSuccess, false) != nil {
			return response, false
		}
		message.Additionals = append(message.Additionals, dnsmessage.Resource{
			Header: header, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{option}},
		})
	}
	packed, err := message.Pack()
	if err != nil {
		return response, false
	}
	return packed, true
}

// relayStatusOf reads the relay option of an answer; false when it has none,
// as from a forwarder that does not relay.
func relayStatusOf(response []byte) (byte, bool) {
	var message dnsmessage.Message
	if message.Unpack(response) != nil {
		return 0, false
	}
	for _, additional := range message.Additionals {
		opt, ok := additional.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, option := range opt.Options {
			if option.Code == ednsOptionRelay && len(option.Data) == 2 && option.Data[0] == relayVersion &&
				option.Data[1] < relayStatusCount {
				return option.Data[1], true
			}
		}
	}
	return 0, false
}

// SetRelay sets what the forwarder relays to: Core's list of the Network
// zones' Internet resolvers for any consumer, those for the consumers of
// scopes only (zones sent to some Device Groups), and the Sites the node
// serves, never asked or told about (DNS design D1c §4, D1c.5).
func (f *ExitForwarder) SetRelay(targets []netip.Addr, scopes []networkmap.RelayScope, served []netip.Prefix) {
	if f == nil {
		return
	}
	allowed := make(map[netip.Addr]struct{}, len(targets))
	for _, target := range targets {
		if internet.Contains(target.Unmap()) {
			allowed[target.Unmap()] = struct{}{}
		}
	}
	scoped := make(map[netip.Addr]map[netip.Addr]struct{})
	for _, scope := range scopes {
		for _, target := range scope.Targets {
			target = target.Unmap()
			if !internet.Contains(target) {
				continue
			}
			if scoped[target] == nil {
				scoped[target] = make(map[netip.Addr]struct{}, len(scope.Sources))
			}
			for _, source := range scope.Sources {
				scoped[target][source.Addr().Unmap()] = struct{}{}
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relayRetired = retireRelays(f.relayRetired, f.relayTargets, f.relayScoped, allowed, scoped, f.clock())
	f.relayTargets, f.relayScoped, f.relayServed = allowed, scoped, slices.Clone(served)
	// What is known of resolvers no longer listed is forgotten.
	listed := func(address netip.Addr) bool {
		_, open := allowed[address]
		_, some := scoped[address]
		_, retired := f.relayRetired[address]
		return open || some || retired
	}
	for address := range f.relayStalled {
		if !listed(address) {
			delete(f.relayStalled, address)
		}
	}
	for address := range f.relayTimedOut {
		if !listed(address) {
			delete(f.relayTimedOut, address)
		}
	}
}

// retireRelays returns the resolvers still relayed to past Core's new list
// (allowed, scoped) at now: what was retired before, until its deadline,
// unless the new list covers it; and, for relayRetireGrace, what the old
// list (targets, scopedBefore) allowed that the new one does not, for any
// consumer or for each source that lost it. Deadlines are never extended:
// only the old list retires anything.
func retireRelays(retired map[netip.Addr]retiredRelay, targets map[netip.Addr]struct{},
	scopedBefore map[netip.Addr]map[netip.Addr]struct{}, allowed map[netip.Addr]struct{},
	scoped map[netip.Addr]map[netip.Addr]struct{}, now time.Time,
) map[netip.Addr]retiredRelay {
	next := make(map[netip.Addr]retiredRelay)
	put := func(address netip.Addr, relay retiredRelay) {
		if !relay.openUntil.IsZero() || len(relay.sources) != 0 {
			next[address] = relay
		}
	}
	for address, relay := range retired {
		if _, open := allowed[address]; open {
			continue
		}
		kept := retiredRelay{sources: map[netip.Addr]time.Time{}}
		if now.Before(relay.openUntil) {
			kept.openUntil = relay.openUntil
		}
		for source, until := range relay.sources {
			if _, listed := scoped[address][source]; !listed && now.Before(until) {
				kept.sources[source] = until
			}
		}
		put(address, kept)
	}
	until := now.Add(relayRetireGrace)
	for address := range targets {
		if _, open := allowed[address]; !open {
			relay := next[address]
			relay.openUntil = until
			put(address, relay)
		}
	}
	for address, sources := range scopedBefore {
		if _, open := allowed[address]; open {
			continue
		}
		relay := next[address]
		for source := range sources {
			if _, listed := scoped[address][source]; listed {
				continue
			}
			if relay.sources == nil {
				relay.sources = map[netip.Addr]time.Time{}
			}
			relay.sources[source] = until
		}
		put(address, relay)
	}
	return next
}

// clock is the forwarder's time.
func (f *ExitForwarder) clock() time.Time {
	if f.now == nil {
		return time.Now()
	}
	return f.now()
}

// ClearRelay forgets every resolver the forwarder relays to, retired ones
// too: the node no longer serves an Exit Pool.
func (f *ExitForwarder) ClearRelay() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relayTargets, f.relayScoped, f.relayServed = nil, nil, nil
	f.relayRetired = map[netip.Addr]retiredRelay{}
	clear(f.relayStalled)
	clear(f.relayTimedOut)
}

// SetUplinkDown records whether the exit node's own way to the Internet is
// down, as its probes measure.
func (f *ExitForwarder) SetUplinkDown(down bool) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uplinkDown = down
}

// relayAllowed reports whether target may be relayed to for consumer:
// listed by Core for any consumer or for a scope consumer is in, on the
// Internet, port 53, outside the exit's own networks and the Sites it
// serves, IPv6 only where the host has IPv6.
func (f *ExitForwarder) relayAllowed(target netip.AddrPort, consumer netip.Addr, private []netip.Prefix) bool {
	address := target.Addr().Unmap()
	f.mu.Lock()
	_, listed := f.relayTargets[address]
	if !listed {
		_, listed = f.relayScoped[address][consumer.Unmap()]
	}
	if retired, known := f.relayRetired[address]; !listed && known {
		now := f.clock()
		listed = now.Before(retired.openUntil) || now.Before(retired.sources[consumer.Unmap()])
	}
	served := slices.Clone(f.relayServed)
	own := slices.Clone(f.addresses)
	f.mu.Unlock()
	inside := func(prefixes []netip.Prefix) bool {
		return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
	}
	switch {
	case !listed, target.Port() != 53, !internet.Contains(address), inside(private), inside(served),
		slices.Contains(own, address):
		return false
	case address.Is6():
		return slices.ContainsFunc(private, func(prefix netip.Prefix) bool {
			return prefix.Addr().Is6() && internet.Contains(prefix.Addr())
		})
	default:
		return true
	}
}

// meshRanges hold the mesh's IPv4 overlay and alias ranges and its own
// IPv6 /48: an answer from the Internet naming one would point the consumer
// into its own mesh (TD-CLI-72). Workspace /48s are added per exit node
// (relayedAnswerHides); the rest of fd00::/8 is ULA a resolver may name.
var meshRanges = append(slices.DeleteFunc(overlayframe.Prefixes(), func(prefix netip.Prefix) bool {
	return prefix.Addr().Is6()
}), netip.MustParsePrefix("fd00::/48"))

// relayedAnswerHides reports an address a relayed answer may not tell: the
// exit's own networks and the Sites it serves, the mesh's ranges, loopback,
// link-local (cloud metadata among them), unspecified and multicast. Other
// private addresses stay: Core lists only resolvers admins chose (DNS design
// D1c Q2).
func relayedAnswerHides(private, served []netip.Prefix, own []netip.Addr) func(netip.Addr) bool {
	mesh := slices.Clone(meshRanges)
	for _, address := range own {
		if address.Is6() {
			mesh = append(mesh, netip.PrefixFrom(address, 48).Masked())
		}
	}
	return func(address netip.Addr) bool {
		address = address.Unmap()
		return address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
			address.IsMulticast() || address.IsUnspecified() ||
			slices.ContainsFunc(mesh, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) ||
			slices.ContainsFunc(private, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) ||
			slices.ContainsFunc(served, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
	}
}

// relay answers a question the consumer asks to relay to target.
func (f *ExitForwarder) relay(ctx context.Context, query []byte, message dnsmessage.Message,
	question dnsmessage.Question, transport string, target netip.AddrPort, consumer netip.Addr, admitted bool,
	private []netip.Prefix,
) []byte {
	answer := func(response []byte, status byte) []byte {
		return markRelayed(query, response, transport, status)
	}
	refused := func(status byte) []byte {
		response := baseResponse(message, Plan{})
		response.RCode = dnsmessage.RCodeRefused
		if status != relayNotAllowed {
			response.RCode = dnsmessage.RCodeServerFailure
		}
		packed, err := response.Pack()
		if err != nil {
			return nil
		}
		return answer(packed, status)
	}
	if !f.relayAllowed(target, consumer, private) {
		return refused(relayNotAllowed)
	}
	if !admitted || !f.holdRelay(target.Addr()) {
		return refused(relayBusy)
	}
	defer f.releaseRelay(target.Addr())
	upstream, err := withoutRelayOption(query)
	if err != nil {
		return refused(relayNotAllowed)
	}
	ask := target
	if f.relayUpstream.IsValid() {
		ask = f.relayUpstream
	}
	relayCtx, cancel := context.WithTimeout(ctx, relayTimeout)
	defer cancel()
	response, err := forwardQuery(relayCtx, upstream, question, []netip.AddrPort{ask}, transport, nil)
	if answered, ok := upstreamAnswer(err); ok {
		// The resolver's own failure (REFUSED, SERVFAIL, ...): its answer.
		response, err = answered, nil
	}
	if err != nil {
		if f.noteRelay(target.Addr(), false) {
			return refused(relayUplinkDown)
		}
		return refused(relayNoAnswer)
	}
	f.noteRelay(target.Addr(), true)
	f.mu.Lock()
	served, own := slices.Clone(f.relayServed), slices.Clone(f.addresses)
	f.mu.Unlock()
	if response, err = withoutPrivateAnswers(response, relayedAnswerHides(private, served, own)); err != nil {
		return refused(relayNoAnswer)
	}
	return answer(response, relayAnswered)
}

// markRelayed is response limited to the asker's UDP size with the relay
// status, which counts within that size (§3). An answer that cannot carry
// the status (unreadable, too large for TCP) becomes a SERVFAIL that does:
// without it the consumer would take the exit node for one that does not
// relay (TD-CLI-72).
func markRelayed(query, response []byte, transport string, status byte) []byte {
	if marked := markRelayedAnswer(query, response, transport, status); marked != nil {
		return marked
	}
	var message dnsmessage.Message
	if message.Unpack(query) != nil {
		return nil
	}
	failure := baseResponse(message, Plan{})
	failure.RCode = dnsmessage.RCodeServerFailure
	packed, err := failure.Pack()
	if err != nil {
		return nil
	}
	if marked, ok := markRelayStatus(query, packed, status); ok {
		return marked
	}
	return nil
}

func markRelayedAnswer(query, response []byte, transport string, status byte) []byte {
	limited, err := limitUDPResponse(query, response, transport)
	if err != nil {
		return nil
	}
	marked, ok := markRelayStatus(query, limited, status)
	if ok && transport == "udp" && len(marked) > udpResponseLimit(query) {
		if limited, err = truncatedResponse(limited); err != nil {
			return nil
		}
		marked, ok = markRelayStatus(query, limited, status)
	}
	if !ok || len(marked) > maxDNSMessageBytes {
		return nil
	}
	return marked
}

// holdRelay counts a question to target, holding back one that keeps not
// answering.
func (f *ExitForwarder) holdRelay(target netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.relayStalled[target] >= relayStalledAfter && f.relayHeld[target] >= maxStalledRelayQuestions {
		return false
	}
	f.relayHeld[target]++
	return true
}

func (f *ExitForwarder) releaseRelay(target netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.relayHeld[target]--; f.relayHeld[target] <= 0 {
		delete(f.relayHeld, target)
	}
}

// noteRelay records whether target answered; it reports, for one that did
// not, whether the exit node's own way to the Internet is down: its probes
// say so, or another resolver began not answering within
// relayTimeoutWindow and nothing (a resolver relayed to, the forwarder's
// upstreams) answered since either began.
// Resolvers that are down themselves while others answer stay their own
// fault.
func (f *ExitForwarder) noteRelay(target netip.Addr, answered bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if answered {
		delete(f.relayStalled, target)
		delete(f.relayTimedOut, target)
		f.relayAnsweredAt = now
		return false
	}
	f.relayStalled[target]++
	// The first timeout of the resolver's run, so that an answer from
	// another resolver after it keeps the uplink up.
	if _, timedOut := f.relayTimedOut[target]; !timedOut {
		f.relayTimedOut[target] = now
	}
	silent, oldest := 0, now
	for address, at := range f.relayTimedOut {
		if now.Sub(at) > relayTimeoutWindow {
			delete(f.relayTimedOut, address)
			continue
		}
		silent++
		if at.Before(oldest) {
			oldest = at
		}
	}
	lastAnswer := f.relayAnsweredAt
	if f.failures == 0 && f.answeredAt.After(lastAnswer) {
		lastAnswer = f.answeredAt
	}
	return f.uplinkDown || (silent >= relayTimeoutsDown && lastAnswer.Before(oldest))
}
