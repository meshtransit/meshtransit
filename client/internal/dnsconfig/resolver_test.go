package dnsconfig

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/networkmap"
	"golang.org/x/net/dns/dnsmessage"
)

func TestResolverEngineLocalRecordsAndNegativeAnswers(t *testing.T) {
	t.Parallel()

	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	engine := newResolverEngine()
	tests := []struct {
		name        string
		queryName   string
		queryType   dnsmessage.Type
		rcode       dnsmessage.RCode
		answerType  dnsmessage.Type
		answerCount int
		authority   bool
	}{
		{
			name:        "ipv4 address",
			queryName:   "NODE-A.EXAMPLE.MESH.",
			queryType:   dnsmessage.TypeA,
			rcode:       dnsmessage.RCodeSuccess,
			answerType:  dnsmessage.TypeA,
			answerCount: 1,
		},
		{
			name:        "ipv6 address",
			queryName:   "node-a.example.mesh.",
			queryType:   dnsmessage.TypeAAAA,
			rcode:       dnsmessage.RCodeSuccess,
			answerType:  dnsmessage.TypeAAAA,
			answerCount: 1,
		},
		{
			name:        "known name without requested type",
			queryName:   "node-b.example.mesh.",
			queryType:   dnsmessage.TypeAAAA,
			rcode:       dnsmessage.RCodeSuccess,
			answerCount: 0,
			authority:   true,
		},
		{
			name:        "unknown authoritative name",
			queryName:   "missing.example.mesh.",
			queryType:   dnsmessage.TypeA,
			rcode:       dnsmessage.RCodeNameError,
			answerCount: 0,
			authority:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			query := packQuery(t, test.queryName, test.queryType)
			response, _ := engine.resolve(t.Context(), plan, query, "udp")
			message := unpackMessage(t, response)
			if message.RCode != test.rcode || len(message.Answers) != test.answerCount {
				t.Fatalf("response rcode=%v answers=%#v", message.RCode, message.Answers)
			}
			if test.answerCount != 0 && message.Answers[0].Header.Type != test.answerType {
				t.Fatalf("answer type = %v, want %v", message.Answers[0].Header.Type, test.answerType)
			}
			if test.authority && len(message.Authorities) != 1 {
				t.Fatalf("authorities = %#v", message.Authorities)
			}
		})
	}
}

func TestResolverEngineRespondsWithSanitizedEDNS0(t *testing.T) {
	t.Parallel()

	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	query := packEDNS0Query(t, "node-a.example.mesh.", dnsmessage.TypeA, 1232)
	response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
	if err != nil {
		t.Fatalf("resolve EDNS0 error = %v", err)
	}
	message := unpackMessage(t, response)
	if len(message.Additionals) != 1 {
		t.Fatalf("additional records = %#v, want one OPT record", message.Additionals)
	}
	additional := message.Additionals[0]
	options, ok := additional.Body.(*dnsmessage.OPTResource)
	if !ok || additional.Header.Name.String() != "." ||
		additional.Header.Class != dnsmessage.Class(maxUDPSize) ||
		additional.Header.TTL != 0 || len(options.Options) != 0 {
		t.Fatalf("EDNS0 response = %#v", additional)
	}
}

func TestResolverEnginePreservesEDNS0OnTruncatedResponse(t *testing.T) {
	t.Parallel()

	query := packEDNS0Query(t, "large.example.mesh.", dnsmessage.TypeA, defaultUDPSize)
	response := unpackMessage(t, packQuery(t, "large.example.mesh.", dnsmessage.TypeA))
	response.Response = true
	response.Authoritative = true
	for index := range 64 {
		response.Answers = append(response.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  response.Questions[0].Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   5,
			},
			Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(index + 1)}},
		})
	}
	packed, err := response.Pack()
	if err != nil {
		t.Fatalf("Pack() response error = %v", err)
	}
	limited, err := limitUDPResponse(query, packed, "udp")
	if err != nil {
		t.Fatalf("limitUDPResponse() error = %v", err)
	}
	message := unpackMessage(t, limited)
	if !message.Truncated || len(message.Answers) != 0 ||
		len(message.Authorities) != 0 || len(message.Additionals) != 1 ||
		message.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("truncated EDNS0 response = %#v", message)
	}
	if len(limited) > defaultUDPSize {
		t.Fatalf("truncated response size = %d, want <= %d", len(limited), defaultUDPSize)
	}
}

func TestResolverEnginePreservesEDNS0OnServerFailure(t *testing.T) {
	t.Parallel()

	query := packEDNS0Query(t, "unrouted.example.", dnsmessage.TypeA, 1232)
	response, err := newResolverEngine().resolve(t.Context(), Plan{Enabled: true}, query, "udp")
	if !errors.Is(err, errNoResolver) {
		t.Fatalf("resolve error = %v, want %v", err, errNoResolver)
	}
	message := unpackMessage(t, response)
	if message.RCode != dnsmessage.RCodeServerFailure ||
		len(message.Additionals) != 1 ||
		message.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("server failure response = %#v", message)
	}
}

func TestResolverEngineRejectsUnsupportedEDNSVersion(t *testing.T) {
	t.Parallel()

	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	query := unpackMessage(t, packEDNS0Query(
		t,
		"node-a.example.mesh.",
		dnsmessage.TypeA,
		1232,
	))
	query.Additionals[0].Header.TTL |= 1 << 16
	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() EDNS version error = %v", err)
	}
	response, err := newResolverEngine().resolve(t.Context(), plan, payload, "udp")
	if err != nil {
		t.Fatalf("resolve unsupported EDNS version error = %v", err)
	}
	message := unpackMessage(t, response)
	if len(message.Answers) != 0 || len(message.Additionals) != 1 ||
		message.Additionals[0].Header.Type != dnsmessage.TypeOPT ||
		message.Additionals[0].Header.ExtendedRCode(message.RCode) != ednsBadVersionRCode {
		t.Fatalf("unsupported EDNS version response = %#v", message)
	}
}

func TestResolverEngineReturnsEDNS0OnMalformedOPT(t *testing.T) {
	t.Parallel()

	query := unpackMessage(t, packEDNS0Query(t, "node-a.example.mesh.", dnsmessage.TypeA, 1232))
	invalidName, err := dnsmessage.NewName("invalid.example.")
	if err != nil {
		t.Fatalf("NewName() error = %v", err)
	}
	query.Additionals[0].Header.Name = invalidName
	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() malformed OPT error = %v", err)
	}
	response, err := newResolverEngine().resolve(t.Context(), Plan{Enabled: true}, payload, "udp")
	if err != nil {
		t.Fatalf("resolve malformed OPT error = %v", err)
	}
	message := unpackMessage(t, response)
	if message.RCode != dnsmessage.RCodeFormatError ||
		len(message.Questions) != 1 || len(message.Additionals) != 1 ||
		message.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("malformed OPT response = %#v", message)
	}
}

func TestResolverEnginePTRAndMalformedQuery(t *testing.T) {
	t.Parallel()

	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	engine := newResolverEngine()
	for _, name := range []string{
		"1.0.64.100.in-addr.arpa.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
	} {
		query := packQuery(t, name, dnsmessage.TypePTR)
		response, err := engine.resolve(t.Context(), plan, query, "udp")
		if err != nil {
			t.Fatalf("resolve PTR %q error = %v", name, err)
		}
		message := unpackMessage(t, response)
		if len(message.Answers) != 1 {
			t.Fatalf("PTR %q answers = %#v", name, message.Answers)
		}
		ptr, ok := message.Answers[0].Body.(*dnsmessage.PTRResource)
		if !ok || ptr.PTR.String() != "node-a.example.mesh." {
			t.Fatalf("PTR %q body = %#v", name, message.Answers[0].Body)
		}
	}

	response, _ := engine.resolve(t.Context(), plan, []byte{0x12, 0x34}, "udp")
	message := unpackMessage(t, response)
	if message.ID != 0x1234 || message.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("format response = %#v", message.Header)
	}
}

func TestResolverEngineForwardsAndRestoresTransactionID(t *testing.T) {
	t.Parallel()

	upstream := startUDPUpstream(t, netip.MustParseAddr("203.0.113.80"))
	plan := Plan{
		Enabled: true,
		Routes: []Route{{
			Suffix:    "corp.example",
			Resolvers: []netip.AddrPort{upstream},
		}},
	}
	query := packQuery(t, "service.corp.example.", dnsmessage.TypeA)
	originalID := binary.BigEndian.Uint16(query[:2])
	response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
	if err != nil {
		t.Fatalf("resolve forwarded error = %v", err)
	}
	message := unpackMessage(t, response)
	if message.ID != originalID || len(message.Answers) != 1 {
		t.Fatalf("forwarded response header=%#v answers=%#v", message.Header, message.Answers)
	}
}

func TestResolverEngineRetriesRetryableUpstreamResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rcode dnsmessage.RCode
	}{
		{name: "server failure", rcode: dnsmessage.RCodeServerFailure},
		{name: "refused", rcode: dnsmessage.RCodeRefused},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			failed := startUDPResponseUpstream(t, test.rcode, netip.Addr{})
			succeeded := startUDPUpstream(t, netip.MustParseAddr("203.0.113.82"))
			plan := Plan{
				Enabled:          true,
				DefaultResolvers: []netip.AddrPort{failed, succeeded},
			}
			query := packQuery(t, "retry.example.", dnsmessage.TypeA)
			response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
			if err != nil {
				t.Fatalf("resolve() error = %v", err)
			}
			message := unpackMessage(t, response)
			if message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 1 {
				t.Fatalf("response rcode=%v answers=%#v", message.RCode, message.Answers)
			}
		})
	}
}

func TestResolverEngineDoesNotRetryNXDOMAIN(t *testing.T) {
	t.Parallel()

	negative := startUDPResponseUpstream(t, dnsmessage.RCodeNameError, netip.Addr{})
	plan := Plan{
		Enabled: true,
		DefaultResolvers: []netip.AddrPort{
			negative,
			netip.MustParseAddrPort("127.0.0.1:1"),
		},
	}
	query := packQuery(t, "missing.example.", dnsmessage.TypeA)
	response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	message := unpackMessage(t, response)
	if message.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("response rcode = %v, want %v", message.RCode, dnsmessage.RCodeNameError)
	}
}

func TestResolverEngineRetriesUnresponsiveUpstream(t *testing.T) {
	t.Parallel()

	unresponsive := startUnresponsiveUDPUpstream(t)
	succeeded := startUDPUpstream(t, netip.MustParseAddr("203.0.113.83"))
	plan := Plan{
		Enabled:          true,
		DefaultResolvers: []netip.AddrPort{unresponsive, succeeded},
	}
	query := packQuery(t, "timeout.example.", dnsmessage.TypeA)
	started := time.Now()
	response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed >= queryTimeout {
		t.Fatalf("resolve() elapsed = %v, want less than %v", elapsed, queryTimeout)
	}
	message := unpackMessage(t, response)
	if message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) != 1 {
		t.Fatalf("response rcode=%v answers=%#v", message.RCode, message.Answers)
	}
}

func TestResolverEngineReturnsServerFailureWhenAllUpstreamsFail(t *testing.T) {
	t.Parallel()

	failed := startUDPResponseUpstream(t, dnsmessage.RCodeServerFailure, netip.Addr{})
	refused := startUDPResponseUpstream(t, dnsmessage.RCodeRefused, netip.Addr{})
	plan := Plan{
		Enabled:          true,
		DefaultResolvers: []netip.AddrPort{failed, refused},
	}
	query := packQuery(t, "failure.example.", dnsmessage.TypeA)
	response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
	if !errors.Is(err, errUpstreamServerFailure) || !errors.Is(err, errUpstreamRefused) {
		t.Fatalf("resolve() error = %v, want both retryable upstream errors", err)
	}
	message := unpackMessage(t, response)
	if message.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("response rcode = %v, want %v", message.RCode, dnsmessage.RCodeServerFailure)
	}
}

func TestResolverEngineRetriesTruncatedUDPOverTCP(t *testing.T) {
	t.Parallel()

	upstream := startTruncatingUpstream(t, netip.MustParseAddr("203.0.113.81"))
	plan := Plan{
		Enabled:          true,
		DefaultResolvers: []netip.AddrPort{upstream},
	}
	query := packQuery(t, "large.example.", dnsmessage.TypeA)
	response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
	if err != nil {
		t.Fatalf("resolve forwarded error = %v", err)
	}
	message := unpackMessage(t, response)
	if message.Truncated || len(message.Answers) != 1 {
		t.Fatalf("forwarded response header=%#v answers=%#v", message.Header, message.Answers)
	}
}

func TestResolverEngineSelectsMostSpecificRouteThenDefault(t *testing.T) {
	t.Parallel()

	defaultResolver := startUDPUpstream(t, netip.MustParseAddr("203.0.113.90"))
	corpResolver := startUDPUpstream(t, netip.MustParseAddr("203.0.113.91"))
	devResolver := startUDPUpstream(t, netip.MustParseAddr("203.0.113.92"))
	plan := Plan{
		Enabled:          true,
		DefaultResolvers: []netip.AddrPort{defaultResolver},
		FallbackResolvers: []netip.AddrPort{
			netip.MustParseAddrPort("127.0.0.1:1"),
		},
		Routes: []Route{
			{Suffix: "corp.example", Resolvers: []netip.AddrPort{corpResolver}},
			{Suffix: "dev.corp.example", Resolvers: []netip.AddrPort{devResolver}},
		},
	}
	tests := []struct {
		name      string
		queryName string
		want      netip.Addr
	}{
		{name: "default", queryName: "public.example.", want: netip.MustParseAddr("203.0.113.90")},
		{name: "split route", queryName: "api.corp.example.", want: netip.MustParseAddr("203.0.113.91")},
		{name: "most specific split route", queryName: "api.dev.corp.example.", want: netip.MustParseAddr("203.0.113.92")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := packQuery(t, test.queryName, dnsmessage.TypeA)
			response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
			if err != nil {
				t.Fatalf("resolve() error = %v", err)
			}
			message := unpackMessage(t, response)
			if len(message.Answers) != 1 {
				t.Fatalf("answers = %#v, want one", message.Answers)
			}
			answer, ok := message.Answers[0].Body.(*dnsmessage.AResource)
			if !ok || netip.AddrFrom4(answer.A) != test.want {
				t.Fatalf("answer = %#v, want %s", message.Answers[0].Body, test.want)
			}
		})
	}
}

func TestResolverEngineDoesNotPromoteFallbackResolverToDefault(t *testing.T) {
	t.Parallel()

	plan := Plan{
		Enabled: true,
		FallbackResolvers: []netip.AddrPort{
			netip.MustParseAddrPort("127.0.0.1:1"),
		},
	}
	query := packQuery(t, "public.example.", dnsmessage.TypeA)
	response, err := newResolverEngine().resolve(t.Context(), plan, query, "udp")
	if !errors.Is(err, errNoResolver) {
		t.Fatalf("resolve() error = %v, want %v", err, errNoResolver)
	}
	message := unpackMessage(t, response)
	if message.RCode != dnsmessage.RCodeServerFailure || message.RecursionAvailable {
		t.Fatalf("fallback-only response header = %#v", message.Header)
	}
}

func TestCompileRejectsTooManyAddressesForOneHost(t *testing.T) {
	t.Parallel()

	snapshot := dnsSnapshot()
	for index := 0; index <= maxAddressesPerHost; index++ {
		snapshot.DNS.Records = append(snapshot.DNS.Records, networkRecord(
			"crowded.example.mesh",
			netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}),
		))
	}
	if _, err := Compile(snapshot); err == nil {
		t.Fatal("Compile() error = nil")
	}
}

func networkRecord(name string, address netip.Addr) networkmap.DNSRecord {
	return networkmap.DNSRecord{Name: name, Type: networkmap.DNSRecordA, Address: address}
}

func packQuery(t *testing.T, name string, recordType dnsmessage.Type) []byte {
	t.Helper()
	dnsName, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName() error = %v", err)
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsName,
			Type:  recordType,
			Class: dnsmessage.ClassINET,
		}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	return query
}

func packEDNS0Query(
	t *testing.T,
	name string,
	recordType dnsmessage.Type,
	udpPayloadSize int,
) []byte {
	t.Helper()

	query := unpackMessage(t, packQuery(t, name, recordType))
	header := dnsmessage.ResourceHeader{}
	if err := header.SetEDNS0(udpPayloadSize, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatalf("SetEDNS0() error = %v", err)
	}
	query.Additionals = []dnsmessage.Resource{{
		Header: header,
		Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{
			Code: 65001,
			Data: []byte{1, 2, 3},
		}}},
	}}
	payload, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() EDNS0 error = %v", err)
	}

	return payload
}

func unpackMessage(t *testing.T, payload []byte) dnsmessage.Message {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(payload); err != nil {
		t.Fatalf("Unpack() error = %v payload=%x", err, payload)
	}

	return message
}

func startUDPUpstream(t *testing.T, answer netip.Addr) netip.AddrPort {
	t.Helper()

	return startUDPResponseUpstream(t, dnsmessage.RCodeSuccess, answer)
}

func startUDPResponseUpstream(
	t *testing.T,
	rcode dnsmessage.RCode,
	answer netip.Addr,
) netip.AddrPort {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	result := make(chan error, 1)
	go func() {
		buffer := make([]byte, maxQueryBytes)
		count, remote, readErr := listener.ReadFromUDPAddrPort(buffer)
		if readErr != nil {
			result <- readErr

			return
		}
		var query dnsmessage.Message
		if unpackErr := query.Unpack(buffer[:count]); unpackErr != nil {
			result <- unpackErr

			return
		}
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 query.ID,
				Response:           true,
				RecursionAvailable: true,
				RCode:              rcode,
			},
			Questions: query.Questions,
		}
		if answer.IsValid() {
			response.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  query.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   30,
				},
				Body: &dnsmessage.AResource{A: answer.As4()},
			}}
		}
		payload, packErr := response.Pack()
		if packErr == nil {
			_, packErr = listener.WriteToUDPAddrPort(payload, remote)
		}
		result <- packErr
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		if err := <-result; err != nil {
			t.Errorf("upstream server error = %v", err)
		}
	})
	localAddress, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("UDP listener address type = %T, want *net.UDPAddr", listener.LocalAddr())
	}
	address := localAddress.AddrPort()

	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), address.Port())
}

func startUnresponsiveUDPUpstream(t *testing.T) netip.AddrPort {
	t.Helper()

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	localAddress, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("UDP listener address type = %T, want *net.UDPAddr", listener.LocalAddr())
	}

	return netip.AddrPortFrom(
		netip.MustParseAddr("127.0.0.1"),
		localAddress.AddrPort().Port(),
	)
}

func startTruncatingUpstream(t *testing.T, answer netip.Addr) netip.AddrPort {
	t.Helper()
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	localAddress, ok := tcpListener.Addr().(*net.TCPAddr)
	if !ok {
		_ = tcpListener.Close()
		t.Fatalf("TCP listener address type = %T, want *net.TCPAddr", tcpListener.Addr())
	}
	port := localAddress.Port
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		_ = tcpListener.Close()
		t.Fatalf("ListenUDP() error = %v", err)
	}
	results := make(chan error, 2)
	go func() {
		buffer := make([]byte, maxQueryBytes)
		count, remote, readErr := udpListener.ReadFromUDPAddrPort(buffer)
		if readErr != nil {
			results <- readErr

			return
		}
		var query dnsmessage.Message
		if unpackErr := query.Unpack(buffer[:count]); unpackErr != nil {
			results <- unpackErr

			return
		}
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, Truncated: true},
			Questions: query.Questions,
		}
		payload, packErr := response.Pack()
		if packErr == nil {
			_, packErr = udpListener.WriteToUDPAddrPort(payload, remote)
		}
		results <- packErr
	}()
	go func() {
		connection, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			results <- acceptErr

			return
		}
		defer func() { _ = connection.Close() }()
		var length uint16
		if readErr := binary.Read(connection, binary.BigEndian, &length); readErr != nil {
			results <- readErr

			return
		}
		queryBytes := make([]byte, int(length))
		if _, readErr := io.ReadFull(connection, queryBytes); readErr != nil {
			results <- readErr

			return
		}
		var query dnsmessage.Message
		if unpackErr := query.Unpack(queryBytes); unpackErr != nil {
			results <- unpackErr

			return
		}
		response := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 query.ID,
				Response:           true,
				RecursionAvailable: true,
			},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  query.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   30,
				},
				Body: &dnsmessage.AResource{A: answer.As4()},
			}},
		}
		payload, packErr := response.Pack()
		if packErr != nil {
			results <- packErr

			return
		}
		payloadLength := len(payload)
		if payloadLength > maxDNSMessageBytes {
			results <- errors.New("packed test response is too large")

			return
		}
		wirePayloadLength := uint16(payloadLength)
		packErr = binary.Write(connection, binary.BigEndian, wirePayloadLength)
		if packErr == nil {
			_, packErr = connection.Write(payload)
		}
		results <- packErr
	}()
	t.Cleanup(func() {
		_ = udpListener.Close()
		_ = tcpListener.Close()
		for range 2 {
			if err := <-results; err != nil {
				t.Errorf("upstream server error = %v", err)
			}
		}
	})

	return netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(port))
}
