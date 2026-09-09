package dnsconfig

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/meshtransit/meshd/internal/networkmap"
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
			if message.Header.RCode != test.rcode || len(message.Answers) != test.answerCount {
				t.Fatalf("response rcode=%v answers=%#v", message.Header.RCode, message.Answers)
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

func TestResolverEnginePTRAndMalformedQuery(t *testing.T) {
	t.Parallel()

	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	engine := newResolverEngine()
	query := packQuery(t, "1.0.64.100.in-addr.arpa.", dnsmessage.TypePTR)
	response, err := engine.resolve(t.Context(), plan, query, "udp")
	if err != nil {
		t.Fatalf("resolve PTR error = %v", err)
	}
	message := unpackMessage(t, response)
	if len(message.Answers) != 1 {
		t.Fatalf("PTR answers = %#v", message.Answers)
	}
	ptr, ok := message.Answers[0].Body.(*dnsmessage.PTRResource)
	if !ok || ptr.PTR.String() != "node-a.example.mesh." {
		t.Fatalf("PTR body = %#v", message.Answers[0].Body)
	}

	response, _ = engine.resolve(t.Context(), plan, []byte{0x12, 0x34}, "udp")
	message = unpackMessage(t, response)
	if message.Header.ID != 0x1234 || message.Header.RCode != dnsmessage.RCodeFormatError {
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
	if message.Header.ID != originalID || len(message.Answers) != 1 {
		t.Fatalf("forwarded response header=%#v answers=%#v", message.Header, message.Answers)
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
	if message.Header.Truncated || len(message.Answers) != 1 {
		t.Fatalf("forwarded response header=%#v answers=%#v", message.Header, message.Answers)
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
				ID:                 query.Header.ID,
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
	address := listener.LocalAddr().(*net.UDPAddr).AddrPort()

	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), address.Port())
}

func startTruncatingUpstream(t *testing.T, answer netip.Addr) netip.AddrPort {
	t.Helper()
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port
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
			Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, Truncated: true},
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
				ID:                 query.Header.ID,
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
		if packErr == nil {
			packErr = binary.Write(connection, binary.BigEndian, uint16(len(payload)))
		}
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
