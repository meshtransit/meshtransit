package dataplane

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/packetmeta"
)

// selfTestWriteOffset leaves room in front of a written packet for the
// headers some TUN implementations prepend (wireguard-go's own offset).
const selfTestWriteOffset = 16

// selfTestPortBase is the first source port of TCP self-tests; each probe
// in flight takes its own.
const selfTestPortBase = 49152

// probeOutcome is what one self-test packet got back.
type probeOutcome int

const (
	// probeUnsent: the packet could not be written into the TUN.
	probeUnsent probeOutcome = iota
	// probeSilent: no answer before the deadline.
	probeSilent
	// probeAnswered: an echo reply, or a TCP SYN-ACK.
	probeAnswered
	// probeRefused: a TCP reset (the host is reachable but its port is
	// closed), or an ICMP error from the Site's network: the self-test
	// crossed the router, the target did not answer it.
	probeRefused
)

// selfTestKey identifies the answer one self-test waits for.
type selfTestKey struct {
	peer     netip.Addr
	protocol uint8
	// port is the target's TCP port, 0 for an echo; id the echo identifier
	// or the TCP source port.
	port, id uint16
}

// selfTester sends a subnet router's self-test packets into the TUN, from
// the overlay frame's first addresses, so they cross the kernel's forward
// path as consumers' packets do (design §6.5.1), and takes their answers
// before the packet filter. Nothing else is ever sent to those addresses.
type selfTester struct {
	mu      sync.Mutex
	write   func([]byte) error
	pending map[selfTestKey]chan probeOutcome
	next    uint16
}

func newSelfTester() *selfTester {
	return &selfTester{pending: map[selfTestKey]chan probeOutcome{}}
}

// attach sets how packets are written into the TUN, as the device that
// reads it is created; nil detaches it.
func (s *selfTester) attach(write func([]byte) error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.write = write
}

// take reports whether packet, read from the TUN, is addressed to a
// self-test address, and records it when it answers a pending self-test.
// Such a packet goes nowhere else.
func (s *selfTester) take(packet []byte) bool {
	if s == nil || len(packet) == 0 {
		return false
	}
	header, err := packetmeta.Parse(packet)
	if err != nil || !overlayframe.IsSelfTest(header.Destination) {
		return false
	}
	key, outcome, ok := answerOf(header)
	if !ok {
		// An ICMP error about a self-test (host unreachable from the
		// Site's gateway) is an answer from the Site's network.
		quoted, isError := packetmeta.ICMPErrorQuote(packet)
		if !isError || !overlayframe.IsSelfTest(quoted.Source) {
			return true
		}
		key, outcome = requestOf(quoted), probeRefused
	}
	s.mu.Lock()
	answered, waiting := s.pending[key]
	if waiting {
		delete(s.pending, key)
	}
	s.mu.Unlock()
	if waiting {
		answered <- outcome
	}
	return true
}

// answerOf names the self-test a packet answers.
func answerOf(header packetmeta.Header) (selfTestKey, probeOutcome, bool) {
	switch {
	case header.Protocol == packetmeta.ProtocolICMPv4 && header.ICMPType == packetmeta.ICMPv4EchoReply,
		header.Protocol == packetmeta.ProtocolICMPv6 && header.ICMPType == packetmeta.ICMPv6EchoReply:
		if !header.HasICMPIdentifier {
			return selfTestKey{}, 0, false
		}
		return selfTestKey{peer: header.Source, protocol: header.Protocol, id: header.ICMPIdentifier}, probeAnswered, true
	case header.Protocol == packetmeta.ProtocolTCP:
		key := selfTestKey{peer: header.Source, protocol: header.Protocol, port: header.SourcePort, id: header.DestinationPort}
		switch {
		case header.TCPFlags&packetmeta.TCPFlagRST != 0:
			return key, probeRefused, true
		case header.TCPFlags&(packetmeta.TCPFlagSYN|packetmeta.TCPFlagACK) == packetmeta.TCPFlagSYN|packetmeta.TCPFlagACK:
			return key, probeAnswered, true
		}
	}
	return selfTestKey{}, 0, false
}

// requestOf names the self-test a quoted self-test packet was.
func requestOf(quoted packetmeta.Header) selfTestKey {
	if quoted.Protocol == packetmeta.ProtocolTCP {
		return selfTestKey{peer: quoted.Destination, protocol: quoted.Protocol, port: quoted.DestinationPort, id: quoted.SourcePort}
	}
	return selfTestKey{peer: quoted.Destination, protocol: quoted.Protocol, id: quoted.ICMPIdentifier}
}

// probe sends one self-test to target (an echo, or a TCP SYN when port is
// not 0) and waits up to wait for its answer. A TCP answer is reset, so the
// target keeps no half-open connection.
func (s *selfTester) probe(ctx context.Context, target netip.Addr, port uint16, wait time.Duration) probeOutcome {
	if s == nil || !target.IsValid() {
		return probeUnsent
	}
	source := overlayframe.SelfTestIPv4
	protocol := packetmeta.ProtocolICMPv4
	if !target.Is4() {
		source, protocol = overlayframe.SelfTestIPv6, packetmeta.ProtocolICMPv6
	}
	s.mu.Lock()
	write := s.write
	s.next++
	id := s.next
	key := selfTestKey{peer: target, protocol: protocol, id: id}
	packet := packetmeta.EchoRequest(source, target, id, 1)
	sequence := uint32(id) << 16
	if port != 0 {
		key = selfTestKey{peer: target, protocol: packetmeta.ProtocolTCP, port: port, id: selfTestPortBase + id%16384}
		packet = packetmeta.TCPSegment(source, target, key.id, port, sequence, 0, packetmeta.TCPFlagSYN)
	}
	if write == nil {
		s.mu.Unlock()
		return probeUnsent
	}
	answered := make(chan probeOutcome, 1)
	s.pending[key] = answered
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
	}()
	if err := write(packet); err != nil {
		return probeUnsent
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case outcome := <-answered:
		if outcome == probeAnswered && port != 0 {
			_ = write(packetmeta.TCPSegment(source, target, key.id, port, sequence+1, 0, packetmeta.TCPFlagRST))
		}
		return outcome
	case <-timer.C:
		return probeSilent
	case <-ctx.Done():
		return probeSilent
	}
}
