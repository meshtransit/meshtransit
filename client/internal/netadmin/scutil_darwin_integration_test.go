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
	// As meshnetd does: an address-less utun marks meshd's lifetime, and the
	// resolver address lives on lo0, where local delivery is guaranteed.
	link, name, err := kernelTUNCreator{}.Open("", 1280, 0, nil, nil)
	if err != nil {
		t.Fatalf("opening the DNS link: %v", err)
	}
	defer func() { _ = link.Close() }()
	if err := (kernelLoopback{}).Add(resolver.Addr()); err != nil {
		t.Fatalf("adding the resolver address to lo0: %v", err)
	}
	defer func() { _ = (kernelLoopback{}).Remove(resolver.Addr()) }()

	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(resolver))
	if err != nil {
		t.Fatalf("listening on the resolver address: %v", err)
	}
	defer func() { _ = listener.Close() }()
	queries := make(chan string, 8)
	go serveTestDNS(listener, answer, queries)

	// Does a packet to the resolver address reach a local socket, or does it
	// go into the utun link?
	route, _ := exec.CommandContext(t.Context(), "/sbin/route", "-n", "get", resolver.Addr().String()).CombinedOutput()
	t.Logf("route to %s:\n%s", resolver.Addr(), route)
	if direct, err := directQuery(resolver); err != nil {
		t.Errorf("a direct UDP query to %s got no answer: %v", resolver, err)
	} else {
		t.Logf("a direct UDP query to %s was answered (%d bytes)", resolver, direct)
	}

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

	// configd merges the entry asynchronously.
	var dump []byte
	for wait := time.Now().Add(10 * time.Second); time.Now().Before(wait); time.Sleep(250 * time.Millisecond) {
		if dump, _ = exec.Command("/usr/sbin/scutil", "--dns").CombinedOutput(); strings.Contains(string(dump), "mttest.mesh") {
			break
		}
	}
	if !strings.Contains(string(dump), "mttest.mesh") {
		script := "show " + scutilIPv4Key + "\nshow " + scutilDNSKey + "\n"
		stored, _ := execScriptRunner{}.RunScript(ctx, DefaultScutilPath, script)
		t.Fatalf("scutil --dns does not list the MeshTransit resolver after 10 s.\nstored entries:\n%s\nscutil --dns:\n%s", stored, dump)
	}
	var output []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lookup, cancelLookup := context.WithTimeout(ctx, 3*time.Second)
		output, _ = exec.CommandContext(lookup, "/usr/bin/dscacheutil", "-q", "host", "-a", "name", "probe.mttest.mesh").CombinedOutput()
		cancelLookup()
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
	if err := (kernelLoopback{}).Remove(resolver.Addr()); err != nil {
		t.Fatalf("removing the resolver address: %v", err)
	}
	if after, _ := exec.CommandContext(ctx, "/sbin/ifconfig", "lo0").CombinedOutput(); strings.Contains(string(after), resolver.Addr().String()) {
		t.Fatal("the resolver address survived its removal from lo0")
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

// directQuery sends one A question for probe.mttest.mesh to the resolver and
// returns the reply size.
func directQuery(resolver netip.AddrPort) (int, error) {
	connection, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(resolver))
	if err != nil {
		return 0, err
	}
	defer func() { _ = connection.Close() }()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	_ = builder.StartQuestions()
	_ = builder.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName("probe.mttest.mesh."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	})
	query, err := builder.Finish()
	if err != nil {
		return 0, err
	}
	if _, err := connection.Write(query); err != nil {
		return 0, err
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 1500)
	return connection.Read(reply)
}
