//go:build integration && darwin

package netadmin

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestScutilSupplementalResolver needs root: sudo go test -tags=integration
// -run TestScutilSupplementalResolver ./client/internal/netadmin/
//
// It checks the whole macOS DNS path meshnetd sets up: a utun link holding the
// resolver address, a resolver on an unprivileged port, the dynamic-store
// entry, and mDNSResponder sending a matching query there.
func TestScutilSupplementalResolver(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating utun links and writing the dynamic store need root")
	}
	resolver := netip.MustParseAddrPort("192.0.2.53:1053")
	answer := netip.MustParseAddr("100.64.9.9")
	link, name, err := kernelTUNCreator{}.Open("", 1280, 0,
		[]netip.Prefix{netip.PrefixFrom(resolver.Addr(), 32)}, nil)
	if err != nil {
		t.Fatalf("opening the DNS link: %v", err)
	}
	defer func() { _ = link.Close() }()

	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(resolver))
	if err != nil {
		t.Fatalf("listening on the resolver address: %v", err)
	}
	defer func() { _ = listener.Close() }()
	queries := make(chan string, 8)
	go serveTestDNS(listener, answer, queries)

	configurator, err := newScutilConfigurator(DefaultScutilPath)
	if err != nil {
		t.Fatal(err)
	}
	config := DNSConfig{
		Endpoint:     DNSEndpoint{InterfaceName: name, Resolver: resolver},
		RouteDomains: []string{"mttest.mesh"},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := configurator.Apply(ctx, config); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer func() { _ = configurator.Reset(context.Background(), config.Endpoint) }()

	if dump, _ := exec.Command("/usr/sbin/scutil", "--dns").CombinedOutput(); !strings.Contains(string(dump), "mttest.mesh") {
		t.Fatalf("scutil --dns does not list the MeshTransit resolver:\n%s", dump)
	}
	var output []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output, _ = exec.Command("/usr/bin/dscacheutil", "-q", "host", "-a", "name", "probe.mttest.mesh").CombinedOutput()
		if strings.Contains(string(output), answer.String()) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !strings.Contains(string(output), answer.String()) {
		t.Fatalf("probe.mttest.mesh did not resolve through MeshTransit DNS:\n%s", output)
	}
	select {
	case question := <-queries:
		t.Logf("resolver on %s answered %s", name, question)
	default:
		t.Fatal("the answer did not come from the test resolver")
	}

	if err := configurator.Reset(ctx, config.Endpoint); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	if dump, _ := exec.Command("/usr/sbin/scutil", "--dns").CombinedOutput(); strings.Contains(string(dump), "mttest.mesh") {
		t.Fatal("the MeshTransit resolver survived Reset")
	}
}

// serveTestDNS answers every A question with answer.
func serveTestDNS(connection *net.UDPConn, answer netip.Addr, queries chan<- string) {
	buffer := make([]byte, 1500)
	for {
		size, source, err := connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(buffer[:size])
		if err != nil {
			continue
		}
		question, err := parser.Question()
		if err != nil {
			continue
		}
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID: header.ID, Response: true, Authoritative: true, RecursionDesired: header.RecursionDesired,
		})
		builder.EnableCompression()
		_ = builder.StartQuestions()
		_ = builder.Question(question)
		_ = builder.StartAnswers()
		if question.Type == dnsmessage.TypeA {
			_ = builder.AResource(dnsmessage.ResourceHeader{
				Name: question.Name, Class: dnsmessage.ClassINET, TTL: 5,
			}, dnsmessage.AResource{A: answer.As4()})
		}
		reply, err := builder.Finish()
		if err != nil {
			continue
		}
		_, _ = connection.WriteToUDPAddrPort(reply, source)
		select {
		case queries <- question.Name.String() + " " + question.Type.String():
		default:
		}
	}
}
