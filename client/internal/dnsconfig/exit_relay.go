package dnsconfig

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/net/dns/dnsmessage"

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
)

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
	if len(response) == 0 {
		return response
	}
	var asked dnsmessage.Message
	if asked.Unpack(query) != nil {
		return response
	}
	if _, present, _ := relayOption(asked); !present {
		return response
	}
	var message dnsmessage.Message
	if message.Unpack(response) != nil {
		return response
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
			return response
		}
		message.Additionals = append(message.Additionals, dnsmessage.Resource{
			Header: header, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{option}},
		})
	}
	packed, err := message.Pack()
	if err != nil {
		return response
	}
	return packed
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
// zones' Internet resolvers, and the Sites the node serves, never asked or
// told about (DNS design D1c §4).
func (f *ExitForwarder) SetRelay(targets []netip.Addr, served []netip.Prefix) {
	if f == nil {
		return
	}
	allowed := make(map[netip.Addr]struct{}, len(targets))
	for _, target := range targets {
		if internet.Contains(target.Unmap()) {
			allowed[target.Unmap()] = struct{}{}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relayTargets, f.relayServed = allowed, slices.Clone(served)
	// What is known of resolvers no longer listed is forgotten.
	for address := range f.relayStalled {
		if _, listed := allowed[address]; !listed {
			delete(f.relayStalled, address)
		}
	}
	for address := range f.relayTimedOut {
		if _, listed := allowed[address]; !listed {
			delete(f.relayTimedOut, address)
		}
	}
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

// relayAllowed reports whether target may be relayed to: listed by Core, on
// the Internet, port 53, outside the exit's own networks and the Sites it
// serves, IPv6 only where the host has IPv6.
func (f *ExitForwarder) relayAllowed(target netip.AddrPort, private []netip.Prefix) bool {
	address := target.Addr().Unmap()
	f.mu.Lock()
	_, listed := f.relayTargets[address]
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

// relayedAnswerHides reports an address a relayed answer may not tell: the
// exit's own networks and the Sites it serves, loopback, link-local (cloud
// metadata among them), unspecified and multicast. Other private addresses
// stay: Core lists only resolvers admins chose (DNS design D1c Q2).
func relayedAnswerHides(private, served []netip.Prefix) func(netip.Addr) bool {
	return func(address netip.Addr) bool {
		address = address.Unmap()
		return address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
			address.IsMulticast() || address.IsUnspecified() ||
			slices.ContainsFunc(private, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) ||
			slices.ContainsFunc(served, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
	}
}

// relay answers a question the consumer asks to relay to target.
func (f *ExitForwarder) relay(ctx context.Context, query []byte, message dnsmessage.Message,
	question dnsmessage.Question, transport string, target netip.AddrPort, admitted bool, private []netip.Prefix,
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
	if !f.relayAllowed(target, private) {
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
	served := slices.Clone(f.relayServed)
	f.mu.Unlock()
	if response, err = withoutPrivateAnswers(response, relayedAnswerHides(private, served)); err != nil {
		return refused(relayNoAnswer)
	}
	return answer(response, relayAnswered)
}

// markRelayed is response limited to the asker's UDP size with the relay
// status, which counts within that size (§3).
func markRelayed(query, response []byte, transport string, status byte) []byte {
	limited, err := limitUDPResponse(query, response, transport)
	if err != nil {
		return nil
	}
	marked := withRelayStatus(query, limited, status)
	if transport == "udp" && len(marked) > udpResponseLimit(query) {
		if limited, err = truncatedResponse(limited); err != nil {
			return nil
		}
		marked = withRelayStatus(query, limited, status)
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
