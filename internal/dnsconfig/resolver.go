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
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
)

var (
	errMalformedQuery = errors.New("dnsconfig: malformed dns query")
	errNoResolver     = errors.New("dnsconfig: no resolver for query")
	errForwardBusy    = errors.New("dnsconfig: forward queue is full")
)

type resolverEngine struct {
	forwardSlots chan struct{}
}

func newResolverEngine() *resolverEngine {
	return &resolverEngine{forwardSlots: make(chan struct{}, maxForwardQueries)}
}

func (e *resolverEngine) resolve(
	ctx context.Context,
	plan Plan,
	query []byte,
	transport string,
) ([]byte, error) {
	message, question, name, err := parseQuery(query)
	if err != nil {
		return formatError(query), nil
	}
	if host, found := findHost(plan.Hosts, name); found {
		response, err := hostResponse(message, question, host, plan)
		if err != nil {
			return nil, err
		}

		return limitUDPResponse(query, response, transport)
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
	if routed && len(route.Resolvers) == 0 {
		response, err := negativeResponse(message, question, dnsmessage.RCodeNameError, route.Suffix, plan)
		if err != nil {
			return nil, err
		}

		return limitUDPResponse(query, response, transport)
	}
	resolvers := plan.DefaultResolvers
	if routed {
		resolvers = route.Resolvers
	}
	if len(resolvers) == 0 {
		response, responseErr := serverFailure(message, question, plan)

		return response, errors.Join(errNoResolver, responseErr)
	}

	select {
	case e.forwardSlots <- struct{}{}:
		defer func() { <-e.forwardSlots }()
	default:
		response, responseErr := serverFailure(message, question, plan)

		return response, errors.Join(errForwardBusy, responseErr)
	}
	forwardCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	response, err := forwardQuery(forwardCtx, query, question, resolvers, transport)
	if err != nil {
		failure, failureErr := serverFailure(message, question, plan)

		return failure, errors.Join(err, failureErr)
	}

	return limitUDPResponse(query, response, transport)
}

func parseQuery(query []byte) (dnsmessage.Message, dnsmessage.Question, string, error) {
	if len(query) < 12 || len(query) > maxQueryBytes {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", errMalformedQuery
	}
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", fmt.Errorf("%w: %v", errMalformedQuery, err)
	}
	if message.Header.Response || message.Header.OpCode != 0 || len(message.Questions) != 1 ||
		len(message.Answers) != 0 || len(message.Authorities) != 0 || len(message.Additionals) > 1 {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", errMalformedQuery
	}
	if len(message.Additionals) == 1 && message.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		return dnsmessage.Message{}, dnsmessage.Question{}, "", errMalformedQuery
	}
	question := message.Questions[0]
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
	response.Header.Authoritative = true
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
	response.Header.Authoritative = true
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

func negativeResponse(
	query dnsmessage.Message,
	_ dnsmessage.Question,
	rcode dnsmessage.RCode,
	zone string,
	plan Plan,
) ([]byte, error) {
	response := baseResponse(query, plan)
	response.Header.Authoritative = true
	response.Header.RCode = rcode
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
	response.Header.RCode = dnsmessage.RCodeServerFailure

	return response.Pack()
}

func baseResponse(query dnsmessage.Message, plan Plan) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			OpCode:             query.Header.OpCode,
			RecursionDesired:   query.Header.RecursionDesired,
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
	if found && len(route.Resolvers) == 0 {
		return route.Suffix
	}

	return name
}

func hasForwardResolvers(plan Plan) bool {
	if len(plan.DefaultResolvers) != 0 {
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

func forwardQuery(
	ctx context.Context,
	query []byte,
	question dnsmessage.Question,
	resolvers []netip.AddrPort,
	transport string,
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
		attemptCtx, cancel := context.WithTimeout(ctx, resolverAttemptTimeout)
		response, err := exchangeDNS(attemptCtx, forwarded, resolver, transport)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("resolver %s: %w", resolver, err))
			continue
		}
		if err := validateForwardResponse(response, binary.BigEndian.Uint16(randomID[:]), question); err != nil {
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
	if transport == "tcp" {
		return exchangeTCP(ctx, query, resolver)
	}
	response, err := exchangeUDP(ctx, query, resolver)
	if err != nil {
		return nil, err
	}
	if isTruncated(response) {
		return exchangeTCP(ctx, query, resolver)
	}

	return response, nil
}

func exchangeUDP(ctx context.Context, query []byte, resolver netip.AddrPort) ([]byte, error) {
	network := "udp4"
	if resolver.Addr().Is6() {
		network = "udp6"
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, resolver.String())
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
	network := "tcp4"
	if resolver.Addr().Is6() {
		network = "tcp6"
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, resolver.String())
	if err != nil {
		return nil, fmt.Errorf("dialing tcp: %w", err)
	}
	defer func() { _ = connection.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting tcp deadline: %w", err)
		}
	}
	if err := binary.Write(connection, binary.BigEndian, uint16(len(query))); err != nil {
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
	if !message.Header.Response || message.Header.OpCode != 0 ||
		len(message.Questions) != 1 || message.Questions[0] != question {
		return errors.New("dnsconfig: upstream response question does not match")
	}

	return nil
}

func isTruncated(message []byte) bool {
	return len(message) >= 4 && binary.BigEndian.Uint16(message[2:4])&(1<<9) != 0
}

func limitUDPResponse(query, response []byte, transport string) ([]byte, error) {
	if transport != "udp" || len(response) <= udpResponseLimit(query) {
		return response, nil
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing oversized response: %w", err)
	}
	message.Header.Truncated = true
	message.Answers = nil
	message.Authorities = nil
	message.Additionals = nil

	return message.Pack()
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
	response, err := message.Pack()
	if err != nil {
		return nil
	}

	return response
}
