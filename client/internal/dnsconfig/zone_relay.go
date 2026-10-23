package dnsconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/shared/internet"
)

// While an exit node is in use, a zone's Internet resolver X is asked
// through the exit node's forwarder: the question goes to the forwarder
// over the mesh with the relay option naming X, and the answer's option
// says what became of it (DNS design D1c §5, exit_relay.go).

// relayOPTSize is the UDP size a question the node gives EDNS asks for.
const relayOPTSize = 1232

var (
	// errRelayNoAnswer: X did not answer the forwarder; it counts against
	// X's breaker.
	errRelayNoAnswer = errors.New("dnsconfig: the zone's resolver did not answer the exit node")
	// errRelaySkipped: the forwarder did not ask X (not allowed, busy, its
	// own way out down); it says nothing of X.
	errRelaySkipped = errors.New("dnsconfig: the exit node did not ask the zone's resolver")
	// errRelayNotAllowed: the exit node may not ask X (not yet, or not for
	// this node); a zone never fails open past it (DNS design D1c.5 §4).
	errRelayNotAllowed = fmt.Errorf("%w: not allowed", errRelaySkipped)
)

// oldExitError is an answer of an exit node that does not relay: its
// forwarder answered the question itself (DNS design D1c Q3).
type oldExitError struct{ response []byte }

func (*oldExitError) Error() string {
	return "dnsconfig: the exit node does not relay to a zone's resolver"
}

// oldExitAnswer returns the forwarder's own answer in err, its ID the
// client's.
func oldExitAnswer(err error) ([]byte, bool) {
	var old *oldExitError
	if errors.As(err, &old) {
		return old.response, true
	}
	return nil, false
}

// relayVia returns the exit node's forwarder that relays to a zone's
// Internet resolvers; not valid without an exit node carrying traffic.
func (e *resolverEngine) relayVia(plan Plan) netip.AddrPort {
	if plan.Exit == nil || len(plan.Exit.Resolvers) == 0 || e.exitPending(plan) {
		return netip.AddrPort{}
	}
	return plan.Exit.Resolvers[0]
}

// relayed reports a resolver asked through via.
func relayed(resolver, via netip.AddrPort) bool {
	return via.IsValid() && internet.Contains(resolver.Addr().Unmap())
}

// zoneResolver reports a resolver of the zone gate is for: only those are
// relayed through an exit node.
func zoneResolver(gate trialGate, resolver netip.AddrPort) bool {
	zone, ok := gate.(zoneGate)
	return ok && slices.Contains(zone.own, resolver)
}

// relayQuery is query asking the forwarder to relay to resolver: any relay
// option the application put in is dropped, and a question without EDNS
// gets it; added reports that.
func relayQuery(query []byte, resolver netip.AddrPort) (relayedQuery []byte, added bool, err error) {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		return nil, false, fmt.Errorf("dnsconfig: reading a question to relay: %w", err)
	}
	option := dnsmessage.Option{Code: ednsOptionRelay, Data: encodeRelayTarget(resolver)}
	found := false
	for index, additional := range message.Additionals {
		opt, ok := additional.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		options := slices.DeleteFunc(slices.Clone(opt.Options), func(existing dnsmessage.Option) bool {
			return existing.Code == ednsOptionRelay
		})
		message.Additionals[index].Body = &dnsmessage.OPTResource{Options: append(options, option)}
		found = true
	}
	if !found {
		var header dnsmessage.ResourceHeader
		if err := header.SetEDNS0(relayOPTSize, dnsmessage.RCodeSuccess, false); err != nil {
			return nil, false, fmt.Errorf("dnsconfig: building EDNS to relay: %w", err)
		}
		message.Additionals = append(message.Additionals, dnsmessage.Resource{
			Header: header, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{option}},
		})
	}
	packed, err := message.Pack()
	if err != nil {
		return nil, false, fmt.Errorf("dnsconfig: writing a question to relay: %w", err)
	}
	return packed, !found, nil
}

// relayedAnswer takes the forwarder's answer to a relayed question: X's
// own answer (status 0) without the relay option, and without EDNS when the
// node added it; an error for any other status, or an oldExitError when the
// forwarder does not relay.
func relayedAnswer(response []byte, addedOPT bool) ([]byte, error) {
	status, marked := relayStatusOf(response)
	switch {
	case marked && status == relayNoAnswer:
		return nil, errRelayNoAnswer
	case marked && status == relayNotAllowed:
		return nil, errRelayNotAllowed
	case marked && status != relayAnswered:
		return nil, fmt.Errorf("%w (status %d)", errRelaySkipped, status)
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: reading a relayed answer: %w", err)
	}
	if addedOPT {
		message.Additionals = slices.DeleteFunc(message.Additionals, func(additional dnsmessage.Resource) bool {
			_, opt := additional.Body.(*dnsmessage.OPTResource)
			return opt
		})
	}
	for index, additional := range message.Additionals {
		if opt, ok := additional.Body.(*dnsmessage.OPTResource); ok {
			options := slices.DeleteFunc(slices.Clone(opt.Options), func(option dnsmessage.Option) bool {
				return option.Code == ednsOptionRelay
			})
			message.Additionals[index].Body = &dnsmessage.OPTResource{Options: options}
		}
	}
	packed, err := message.Pack()
	if err != nil {
		return nil, fmt.Errorf("dnsconfig: writing a relayed answer: %w", err)
	}
	if !marked {
		return nil, &oldExitError{response: packed}
	}
	return packed, nil
}
