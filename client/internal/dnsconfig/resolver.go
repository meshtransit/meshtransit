package dnsconfig

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/underlay"
	"meshtransit.net/shared/internet"
)

const (
	positiveTTL            = 5 * time.Second
	negativeTTL            = 10 * time.Second
	queryTimeout           = 5 * time.Second
	resolverAttemptTimeout = 1500 * time.Millisecond
	maxQueryBytes          = 4096
	maxDNSMessageBytes     = 65535
	defaultUDPSize         = 512
	maxUDPSize             = 4096
	maxForwardQueries      = 128
	ednsBadVersionRCode    = dnsmessage.RCode(16)
)

var (
	errMalformedQuery         = errors.New("dnsconfig: malformed dns query")
	errUnsupportedEDNSVersion = errors.New("dnsconfig: unsupported EDNS version")
	errNoResolver             = errors.New("dnsconfig: no resolver for query")
	errForwardBusy            = errors.New("dnsconfig: forward queue is full")
	errUnreachableResolver    = errors.New("dnsconfig: resolver not reachable from this network")
	errUpstreamServerFailure  = errors.New("dnsconfig: upstream returned server failure")
	errUpstreamRefused        = errors.New("dnsconfig: upstream refused query")
)

// upstreamAnswerError is a resolver's SERVFAIL or REFUSED answer, kept with
// the error forwardQuery returns: the resolver answered, about the name (a
// filter blocking it, DNSSEC), so a zone never fails open past it (DNS
// design D1b §5.3).
type upstreamAnswerError struct {
	response []byte
	err      error
}

func (e *upstreamAnswerError) Error() string { return e.err.Error() }

func (e *upstreamAnswerError) Unwrap() error { return e.err }

// upstreamAnswer returns the first SERVFAIL or REFUSED answer in err, its
// ID the client's.
func upstreamAnswer(err error) ([]byte, bool) {
	var answered *upstreamAnswerError
	if errors.As(err, &answered) {
		return answered.response, true
	}
	return nil, false
}

type resolverEngine struct {
	forwardSlots chan struct{}
	// captive is set while a captive portal window is open: names the exit
	// node would answer go to networkResolvers instead (exit node design
	// §17.5).
	captive          atomic.Bool
	networkResolvers func() []netip.AddrPort
	// breaker skips forward zone resolvers that keep failing.
	breaker *resolverBreaker
	// network caches networkResolvers for zones that fail open.
	network networkResolverCache
	// fullResolver answers every name, not only the mesh's: names no route
	// covers go to networkResolvers when the plan names no resolver for
	// them (PacketResolver, a platform without split DNS).
	fullResolver bool
	// failuresAsNXDOMAIN answers a zone's failures NXDOMAIN with an
	// Extended DNS Error instead of SERVFAIL or a resolver's REFUSED
	// (Android; failure.go).
	failuresAsNXDOMAIN bool
	// exitRouted, when set, reports whether the host's Internet routes go
	// into the mesh now; until the plan has the exit node's resolvers, no
	// question may then leave through the host's own network.
	exitRouted func() bool
	// liveness, when set, orders the zones' resolver Devices (liveness.go).
	liveness atomic.Pointer[ResolverLiveness]
	// infrastructure are the names of MeshTransit's own infrastructure the
	// root zone leaves to the network (root.go).
	infrastructure atomic.Pointer[map[string]struct{}]
	// health is what the zones' resolvers last answered (health.go).
	health *resolverHealthTracker
	// networkGeneration, when set, changes whenever networkResolvers would
	// return other resolvers: the cache is then refreshed at once.
	networkGeneration func() uint64
}

// networkTargets are the host's network resolvers, from the cache.
func (e *resolverEngine) networkTargets() []netip.AddrPort {
	var generation uint64
	if e.networkGeneration != nil {
		generation = e.networkGeneration()
	}
	return e.network.resolvers(e.networkResolvers, generation)
}

// exitPending reports a host routing the Internet into the mesh before the
// plan knows the exit node's resolvers: names the exit node would answer
// get none, and none goes to a resolver on the Internet or the network.
func (e *resolverEngine) exitPending(plan Plan) bool {
	return plan.Exit == nil && e.exitRouted != nil && e.exitRouted()
}

func newResolverEngine() *resolverEngine {
	return &resolverEngine{
		forwardSlots: make(chan struct{}, maxForwardQueries), networkResolvers: underlay.NetworkResolvers,
		breaker: newResolverBreaker(time.Now), health: newResolverHealthTracker(time.Now),
	}
}

func (e *resolverEngine) resolve(
	ctx context.Context,
	plan Plan,
	query []byte,
	transport string,
) ([]byte, error) {
	message, question, name, err := parseQuery(query)
	if err != nil {
		if errors.Is(err, errUnsupportedEDNSVersion) {
			return unsupportedEDNSVersionResponse(message)
		}

		return formatError(query), nil
	}
	if response, own, err := ownNameAnswer(plan, message, question, name); own {
		if err != nil {
			return nil, err
		}
		return limitUDPResponse(query, response, transport)
	}
	if host, found := findHost(plan.Hosts, name); found {
		if route, pass := passesThrough(plan, name, question.Type); pass {
			return e.resolveZone(ctx, zoneQuery{
				plan: plan, route: route, query: query, message: message,
				question: question, transport: transport,
			})
		}
		response, err := hostResponse(message, question, host, plan)
		if err != nil {
			return nil, err
		}

		return limitUDPResponse(query, response, transport)
	}
	if _, found := findAlias(plan.Aliases, name); found {
		return e.resolveAlias(ctx, aliasQuery{
			plan: plan, query: query, message: message, question: question,
			name: name, transport: transport,
		})
	}
	if question.Type == dnsmessage.TypePTR {
		if address, ok := parseReverseName(name); ok {
			if reverse, found := findReverse(plan.Reverse, address); found {
				response, err := ptrResponse(message, question, reverse, plan)
				if err != nil {
					return nil, err
				}

				return limitUDPResponse(query, response, transport)
			}
		}
	}

	route, routed := mostSpecificRoute(plan.Routes, name)
	if routed && route.local() {
		// A name that holds other names exists: no data, not NXDOMAIN.
		rcode := dnsmessage.RCodeNameError
		if isInterior(plan, name) {
			rcode = dnsmessage.RCodeSuccess
		}
		response, err := negativeResponse(message, question, rcode, route.Suffix, plan)
		if err != nil {
			return nil, err
		}

		return limitUDPResponse(query, response, transport)
	}
	if routed {
		return e.resolveZone(ctx, zoneQuery{
			plan: plan, route: route, query: query, message: message,
			question: question, transport: transport,
		})
	}
	if plan.RoutesAllNames() {
		unrouted := zoneQuery{plan: plan, query: query, message: message, question: question, transport: transport}
		if response, handled, err := e.resolveUnrouted(ctx, unrouted, name); handled {
			return response, err
		}
	}
	resolvers := plan.DefaultResolvers
	captiveWindow := false
	if exit := plan.Exit; exit != nil {
		// Every name no route covers goes to the exit node, never to a
		// resolver on the Internet through the host's own network.
		var private []netip.AddrPort
		network := e.captiveResolvers()
		switch {
		case len(network) != 0:
			// A captive portal window: the network's resolvers, from the
			// client's own sockets, and answers that soon expire.
			captiveWindow, private = true, network
		default:
			if question.Type == dnsmessage.TypeAAAA && !exit.IPv6 {
				response, err := noDataResponse(message, question, plan)
				if err != nil {
					return nil, err
				}
				return limitUDPResponse(query, response, transport)
			}
			// Compile admitted only the exit node's own mesh addresses.
			private = exit.Resolvers
		}
		resolvers = private
	} else if e.exitPending(plan) {
		// Only resolvers in the mesh, which the exit route never carries.
		resolvers = slices.DeleteFunc(slices.Clone(resolvers), func(resolver netip.AddrPort) bool {
			address := resolver.Addr().Unmap()
			return !overlayframe.Contains(netip.PrefixFrom(address, address.BitLen()))
		})
	} else if len(resolvers) == 0 && e.fullResolver {
		resolvers = e.networkTargets()
	}
	if len(resolvers) == 0 {
		return failureResponse(query, message, question, plan, transport, errNoResolver)
	}

	select {
	case e.forwardSlots <- struct{}{}:
		defer func() { <-e.forwardSlots }()
	default:
		return failureResponse(query, message, question, plan, transport, errForwardBusy)
	}
	forwardCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	response, err := forwardQuery(forwardCtx, query, question, resolvers, transport, nil)
	if err != nil {
		return failureResponse(query, message, question, plan, transport, err)
	}
	if response, err = sanitizeAnswer(plan, question, response); err != nil {
		return failureResponse(query, message, question, plan, transport, err)
	}
	if captiveWindow {
		if response, err = capTTLs(response, uint32(positiveTTL/time.Second)); err != nil {
			return failureResponse(query, message, question, plan, transport, err)
		}
	}

	return limitUDPResponse(query, response, transport)
}

func parseQuery(query []byte) (dnsmessage.Message, dnsmessage.Question, string, error) {
	if len(query) < 12 || len(query) > maxQueryBytes {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", errMalformedQuery
	}
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", fmt.Errorf("%w: %w", errMalformedQuery, err)
	}
	if message.Response || message.OpCode != 0 || len(message.Questions) != 1 ||
		len(message.Answers) != 0 || len(message.Authorities) != 0 || len(message.Additionals) > 1 {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", errMalformedQuery
	}
	question := message.Questions[0]
	if len(message.Additionals) == 1 {
		additional := message.Additionals[0]
		if additional.Header.Type != dnsmessage.TypeOPT || additional.Header.Name.String() != "." {
			return dnsmessage.Message{}, dnsmessage.Question{}, "", errMalformedQuery
		}
		if additional.Header.TTL>>16&0xff != 0 {
			return message, question, "", errUnsupportedEDNSVersion
		}
	}
	if question.Class != dnsmessage.ClassINET {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", errMalformedQuery
	}
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	if name == "" {
		name = "."
	}

	return message, question, name, nil
}

func hostResponse(
	query dnsmessage.Message,
	question dnsmessage.Question,
	host Host,
	plan Plan,
) ([]byte, error) {
	response := baseResponse(query, plan)
	response.Authoritative = true
	for _, address := range host.Addresses {
		switch {
		case address.Is4() && (question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeALL):
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   uint32(positiveTTL / time.Second),
				},
				Body: &dnsmessage.AResource{A: address.As4()},
			})
		case address.Is6() && (question.Type == dnsmessage.TypeAAAA || question.Type == dnsmessage.TypeALL):
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   uint32(positiveTTL / time.Second),
				},
				Body: &dnsmessage.AAAAResource{AAAA: address.As16()},
			})
		}
	}
	if len(response.Answers) == 0 {
		zone := authoritativeZone(plan.Routes, strings.TrimSuffix(strings.ToLower(question.Name.String()), "."))
		if err := appendSOA(&response, zone); err != nil {
			return nil, err
		}
	}

	return response.Pack()
}

func ptrResponse(
	query dnsmessage.Message,
	question dnsmessage.Question,
	reverse Reverse,
	plan Plan,
) ([]byte, error) {
	name, err := dnsName(reverse.Name)
	if err != nil {
		return nil, err
	}
	response := baseResponse(query, plan)
	response.Authoritative = true
	response.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
			TTL:   uint32(positiveTTL / time.Second),
		},
		Body: &dnsmessage.PTRResource{PTR: name},
	}}

	return response.Pack()
}

// noDataResponse answers that the name has no record of the question's
// type, which a client takes at once, unlike a timeout.
func noDataResponse(query dnsmessage.Message, question dnsmessage.Question, plan Plan) ([]byte, error) {
	return negativeResponse(query, question, dnsmessage.RCodeSuccess, ".", plan)
}

func negativeResponse(
	query dnsmessage.Message,
	_ dnsmessage.Question,
	rcode dnsmessage.RCode,
	zone string,
	plan Plan,
) ([]byte, error) {
	response := baseResponse(query, plan)
	response.Authoritative = true
	response.RCode = rcode
	if err := appendSOA(&response, zone); err != nil {
		return nil, err
	}

	return response.Pack()
}

func serverFailure(
	query dnsmessage.Message,
	_ dnsmessage.Question,
	plan Plan,
) ([]byte, error) {
	response := baseResponse(query, plan)
	response.RCode = dnsmessage.RCodeServerFailure

	return response.Pack()
}

func failureResponse(
	query []byte,
	request dnsmessage.Message,
	question dnsmessage.Question,
	plan Plan,
	transport string,
	cause error,
) ([]byte, error) {
	response, responseErr := serverFailure(request, question, plan)
	response, limitErr := limitUDPResponse(query, response, transport)

	return response, errors.Join(cause, responseErr, limitErr)
}

func unsupportedEDNSVersionResponse(query dnsmessage.Message) ([]byte, error) {
	response := baseResponse(query, Plan{})
	header := dnsmessage.ResourceHeader{}
	if err := header.SetEDNS0(maxUDPSize, ednsBadVersionRCode, false); err != nil {
		return nil, fmt.Errorf("dnsconfig: building unsupported EDNS version response: %w", err)
	}
	response.Additionals = []dnsmessage.Resource{{
		Header: header,
		Body:   &dnsmessage.OPTResource{},
	}}
	packed, err := response.Pack()
	if err != nil {
		return nil, fmt.Errorf("dnsconfig: packing unsupported EDNS version response: %w", err)
	}

	return packed, nil
}

func baseResponse(query dnsmessage.Message, plan Plan) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.ID,
			Response:           true,
			OpCode:             query.OpCode,
			RecursionDesired:   query.RecursionDesired,
			RecursionAvailable: hasForwardResolvers(plan),
		},
		Questions: append([]dnsmessage.Question(nil), query.Questions...),
	}
}

func appendSOA(response *dnsmessage.Message, zone string) error {
	zoneName, err := dnsName(zone)
	if err != nil {
		return err
	}
	ns, err := dnsmessage.NewName("ns.meshtransit.invalid.")
	if err != nil {
		return fmt.Errorf("dnsconfig: building soa ns name: %w", err)
	}
	mailbox, err := dnsmessage.NewName("hostmaster.meshtransit.invalid.")
	if err != nil {
		return fmt.Errorf("dnsconfig: building soa mailbox: %w", err)
	}
	response.Authorities = append(response.Authorities, dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  zoneName,
			Type:  dnsmessage.TypeSOA,
			Class: dnsmessage.ClassINET,
			TTL:   uint32(negativeTTL / time.Second),
		},
		Body: &dnsmessage.SOAResource{
			NS:      ns,
			MBox:    mailbox,
			Serial:  1,
			Refresh: uint32(negativeTTL / time.Second),
			Retry:   uint32(negativeTTL / time.Second),
			Expire:  uint32(negativeTTL / time.Second),
			MinTTL:  uint32(negativeTTL / time.Second),
		},
	})

	return nil
}

func dnsName(name string) (dnsmessage.Name, error) {
	if name == "." {
		return dnsmessage.NewName(".")
	}
	parsed, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return dnsmessage.Name{}, fmt.Errorf("dnsconfig: building dns name: %w", err)
	}

	return parsed, nil
}

func findHost(hosts []Host, name string) (Host, bool) {
	index, found := slices.BinarySearchFunc(hosts, name, func(host Host, target string) int {
		return strings.Compare(host.Name, target)
	})
	if !found {
		return Host{}, false
	}

	return hosts[index], true
}

func findReverse(records []Reverse, address netip.Addr) (Reverse, bool) {
	index, found := slices.BinarySearchFunc(records, address, func(record Reverse, target netip.Addr) int {
		return record.Address.Compare(target)
	})
	if !found {
		return Reverse{}, false
	}

	return records[index], true
}

func mostSpecificRoute(routes []Route, name string) (Route, bool) {
	best := Route{}
	found := false
	for _, route := range routes {
		if !dnsSuffixContains(route.Suffix, name) || (found && len(route.Suffix) <= len(best.Suffix)) {
			continue
		}
		best = route
		found = true
	}

	return best, found
}

func authoritativeZone(routes []Route, name string) string {
	route, found := mostSpecificRoute(routes, name)
	if found && route.local() {
		return route.Suffix
	}

	return name
}

func hasForwardResolvers(plan Plan) bool {
	if len(plan.DefaultResolvers) != 0 || (plan.Root != nil && len(plan.Root.Resolvers) != 0) {
		return true
	}
	return slices.ContainsFunc(plan.Routes, func(route Route) bool {
		return len(route.Resolvers) != 0
	})
}

func parseReverseName(name string) (netip.Addr, bool) {
	if labels, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		parts := strings.Split(labels, ".")
		if len(parts) != 4 {
			return netip.Addr{}, false
		}
		slices.Reverse(parts)
		address, err := netip.ParseAddr(strings.Join(parts, "."))

		return address, err == nil && address.Is4()
	}
	if labels, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		parts := strings.Split(labels, ".")
		if len(parts) != 32 {
			return netip.Addr{}, false
		}
		slices.Reverse(parts)
		for _, part := range parts {
			if len(part) != 1 || !strings.ContainsRune("0123456789abcdef", rune(part[0])) {
				return netip.Addr{}, false
			}
		}
		hex := strings.Join(parts, "")
		groups := make([]string, 0, 8)
		for index := 0; index < len(hex); index += 4 {
			groups = append(groups, hex[index:index+4])
		}
		address, err := netip.ParseAddr(strings.Join(groups, ":"))

		return address, err == nil && address.Is6()
	}

	return netip.Addr{}, false
}

// trialGate decides which resolvers forwardQuery asks and learns how each
// trial went (resolverBreaker through zoneGate).
type trialGate interface {
	allow(netip.AddrPort) bool
	record(netip.AddrPort, error)
	release(netip.AddrPort)
}

// forwardQuery asks resolvers in order until one answers; gate, when not
// nil, skips resolvers and learns from each trial.
func forwardQuery(
	ctx context.Context,
	query []byte,
	question dnsmessage.Question,
	resolvers []netip.AddrPort,
	transport string,
	gate trialGate,
) ([]byte, error) {
	forwarded := append([]byte(nil), query...)
	originalID := binary.BigEndian.Uint16(forwarded[:2])
	var randomID [2]byte
	if _, err := io.ReadFull(rand.Reader, randomID[:]); err != nil {
		return nil, fmt.Errorf("dnsconfig: generating upstream transaction id: %w", err)
	}
	binary.BigEndian.PutUint16(forwarded[:2], binary.BigEndian.Uint16(randomID[:]))
	var failures []error
	for _, resolver := range resolvers {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(append(failures, err)...)
		}
		if gate != nil && !gate.allow(resolver) {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, resolverAttemptTimeout)
		response, err := exchangeDNS(attemptCtx, forwarded, resolver, transport)
		cancel()
		if err == nil {
			err = validateForwardResponse(response, binary.BigEndian.Uint16(randomID[:]), question)
		}
		if gate != nil {
			switch {
			case err == nil || answeredWith(err):
				// It answered: SERVFAIL or REFUSED is about the name or the
				// type (DNSSEC, views), not the resolver.
				gate.record(resolver, err)
			case ctx.Err() != nil || transport == "tcp":
				// The question was given up or ran out of its budget, or
				// only TCP failed (policy may admit UDP alone): not the
				// resolver's fault.
				gate.release(resolver)
			default:
				gate.record(resolver, err)
			}
		}
		if err != nil {
			if errors.Is(err, errUpstreamServerFailure) || errors.Is(err, errUpstreamRefused) {
				binary.BigEndian.PutUint16(response[:2], originalID)
				err = &upstreamAnswerError{response: response, err: err}
			}
			failures = append(failures, fmt.Errorf("resolver %s: %w", resolver, err))
			continue
		}
		binary.BigEndian.PutUint16(response[:2], originalID)

		return response, nil
	}
	if len(failures) == 0 {
		return nil, errNoResolver
	}

	return nil, errors.Join(failures...)
}

func exchangeDNS(
	ctx context.Context,
	query []byte,
	resolver netip.AddrPort,
	transport string,
) ([]byte, error) {
	if unreachableResolver(resolver.Addr()) {
		return nil, errUnreachableResolver
	}
	if transport == "tcp" {
		return exchangeTCP(ctx, query, resolver)
	}
	response, err := exchangeUDP(ctx, query, resolver)
	if err != nil {
		return nil, err
	}
	if isTruncated(response) {
		// Without TCP to the resolver (a rule may admit UDP alone), the
		// truncated answer still tells the client to ask over TCP.
		if full, tcpErr := exchangeTCP(ctx, query, resolver); tcpErr == nil {
			return full, nil
		}
	}

	return response, nil
}

// unreachableResolver reports a resolver at a private address outside the
// mesh the platform says the client cannot reach (underlay.SetPrivateReach).
func unreachableResolver(address netip.Addr) bool {
	address = address.Unmap()
	if overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) || internet.Contains(address) {
		return false
	}
	return !underlay.PrivateReachable(address)
}

// dialerFor keeps a socket to a resolver on the physical network, except
// to one in the mesh (an exit node's forwarder), which only the mesh
// reaches, and, on a mobile VPN, to one inside a subnet route on its
// interface (a zone's resolver in a Site), reached through the Site.
func dialerFor(resolver netip.AddrPort) *net.Dialer {
	address := resolver.Addr().Unmap()
	if overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) || underlay.ThroughMesh(address) {
		return &net.Dialer{}
	}
	return underlay.Dialer(0)
}

func exchangeUDP(ctx context.Context, query []byte, resolver netip.AddrPort) ([]byte, error) {
	network := "udp4"
	if resolver.Addr().Is6() {
		network = "udp6"
	}
	connection, err := dialerFor(resolver).DialContext(ctx, network, resolver.String())
	if err != nil {
		return nil, fmt.Errorf("dialing udp: %w", err)
	}
	defer func() { _ = connection.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting udp deadline: %w", err)
		}
	}
	if _, err := connection.Write(query); err != nil {
		return nil, fmt.Errorf("writing udp query: %w", err)
	}
	buffer := make([]byte, maxDNSMessageBytes)
	count, err := connection.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("reading udp response: %w", err)
	}

	return append([]byte(nil), buffer[:count]...), nil
}

func exchangeTCP(ctx context.Context, query []byte, resolver netip.AddrPort) ([]byte, error) {
	queryLength := len(query)
	if queryLength > maxDNSMessageBytes {
		return nil, errors.New("dnsconfig: tcp query is too large")
	}
	wireQueryLength := uint16(queryLength)

	network := "tcp4"
	if resolver.Addr().Is6() {
		network = "tcp6"
	}
	connection, err := dialerFor(resolver).DialContext(ctx, network, resolver.String())
	if err != nil {
		return nil, fmt.Errorf("dialing tcp: %w", err)
	}
	defer func() { _ = connection.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting tcp deadline: %w", err)
		}
	}
	if err := binary.Write(connection, binary.BigEndian, wireQueryLength); err != nil {
		return nil, fmt.Errorf("writing tcp query length: %w", err)
	}
	if _, err := connection.Write(query); err != nil {
		return nil, fmt.Errorf("writing tcp query: %w", err)
	}
	var length uint16
	if err := binary.Read(connection, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("reading tcp response length: %w", err)
	}
	if length < 12 {
		return nil, errors.New("dnsconfig: upstream tcp response is too short")
	}
	response := make([]byte, int(length))
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, fmt.Errorf("reading tcp response: %w", err)
	}

	return response, nil
}

func validateForwardResponse(
	response []byte,
	transactionID uint16,
	question dnsmessage.Question,
) error {
	if len(response) < 12 || len(response) > maxDNSMessageBytes ||
		binary.BigEndian.Uint16(response[:2]) != transactionID {
		return errors.New("dnsconfig: upstream response transaction does not match")
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return fmt.Errorf("dnsconfig: parsing upstream response: %w", err)
	}
	if !message.Response || message.OpCode != 0 ||
		len(message.Questions) != 1 || message.Questions[0] != question {
		return errors.New("dnsconfig: upstream response question does not match")
	}
	switch message.RCode {
	case dnsmessage.RCodeServerFailure:
		return errUpstreamServerFailure
	case dnsmessage.RCodeRefused:
		return errUpstreamRefused
	}

	return nil
}

func isTruncated(message []byte) bool {
	return len(message) >= 4 && binary.BigEndian.Uint16(message[2:4])&(1<<9) != 0
}

func limitUDPResponse(query, response []byte, transport string) ([]byte, error) {
	response, err := addEDNS0Response(query, response)
	if err != nil {
		return nil, err
	}
	if transport != "udp" || len(response) <= udpResponseLimit(query) {
		return response, nil
	}

	return truncatedResponse(response)
}

// truncatedResponse is response without its records, marked truncated: the
// asker should ask again over TCP.
func truncatedResponse(response []byte) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing oversized response: %w", err)
	}
	message.Truncated = true
	message.Answers = nil
	message.Authorities = nil
	message.Additionals = slices.DeleteFunc(message.Additionals, func(resource dnsmessage.Resource) bool {
		return resource.Header.Type != dnsmessage.TypeOPT
	})

	return message.Pack()
}

func addEDNS0Response(query, response []byte) ([]byte, error) {
	var queryMessage dnsmessage.Message
	if err := queryMessage.Unpack(query); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing query for EDNS0: %w", err)
	}
	if len(queryMessage.Additionals) == 0 {
		return response, nil
	}
	if queryMessage.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		return response, nil
	}

	var responseMessage dnsmessage.Message
	if err := responseMessage.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing response for EDNS0: %w", err)
	}
	additionals := make([]dnsmessage.Resource, 0, len(responseMessage.Additionals)+1)
	for _, additional := range responseMessage.Additionals {
		if additional.Header.Type != dnsmessage.TypeOPT {
			additionals = append(additionals, additional)
		}
	}
	header := dnsmessage.ResourceHeader{}
	if err := header.SetEDNS0(
		maxUDPSize,
		dnsmessage.RCodeSuccess,
		false,
	); err != nil {
		return nil, fmt.Errorf("dnsconfig: building EDNS0 response: %w", err)
	}
	responseMessage.Additionals = additionals
	responseMessage.Additionals = append(responseMessage.Additionals, dnsmessage.Resource{
		Header: header,
		Body:   &dnsmessage.OPTResource{},
	})

	packed, err := responseMessage.Pack()
	if err != nil {
		return nil, fmt.Errorf("dnsconfig: packing EDNS0 response: %w", err)
	}

	return packed, nil
}

func udpResponseLimit(query []byte) int {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		return defaultUDPSize
	}
	limit := defaultUDPSize
	for _, additional := range message.Additionals {
		if additional.Header.Type != dnsmessage.TypeOPT {
			continue
		}
		limit = int(additional.Header.Class)
		break
	}
	if limit < defaultUDPSize {
		return defaultUDPSize
	}
	if limit > maxUDPSize {
		return maxUDPSize
	}

	return limit
}

func formatError(query []byte) []byte {
	id := uint16(0)
	if len(query) >= 2 {
		id = binary.BigEndian.Uint16(query[:2])
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{
		ID:       id,
		Response: true,
		RCode:    dnsmessage.RCodeFormatError,
	}}
	var request dnsmessage.Message
	if err := request.Unpack(query); err == nil {
		message.OpCode = request.OpCode
		message.RecursionDesired = request.RecursionDesired
		if len(request.Questions) == 1 {
			message.Questions = append(message.Questions, request.Questions[0])
		}
		if slices.ContainsFunc(request.Additionals, func(resource dnsmessage.Resource) bool {
			return resource.Header.Type == dnsmessage.TypeOPT
		}) {
			header := dnsmessage.ResourceHeader{}
			if err := header.SetEDNS0(maxUDPSize, dnsmessage.RCodeSuccess, false); err == nil {
				message.Additionals = []dnsmessage.Resource{{
					Header: header,
					Body:   &dnsmessage.OPTResource{},
				}}
			}
		}
	}
	response, err := message.Pack()
	if err != nil {
		return nil
	}

	return response
}

// captiveResolvers are the network's resolvers while a captive portal window
// is open; none otherwise.
func (e *resolverEngine) captiveResolvers() []netip.AddrPort {
	if !e.captive.Load() || e.networkResolvers == nil {
		return nil
	}
	return e.networkResolvers()
}

// capTTLs lowers every record's TTL in response to at most limit seconds,
// the OPT pseudo-record's flags kept: a captive portal's network answers
// must not outlive its window in any cache.
func capTTLs(response []byte, limit uint32) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: reading the network's answer: %w", err)
	}
	for _, section := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
		for index := range section {
			if section[index].Header.Type != dnsmessage.TypeOPT {
				section[index].Header.TTL = min(section[index].Header.TTL, limit)
			}
		}
	}
	capped, err := message.Pack()
	if err != nil {
		return nil, fmt.Errorf("dnsconfig: writing the network's answer: %w", err)
	}
	return capped, nil
}
