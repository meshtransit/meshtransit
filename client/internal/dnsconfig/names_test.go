package dnsconfig

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/networkmap"
)

// startScriptedUpstream answers every UDP question with what reply builds
// from it, until the test ends.
func startScriptedUpstream(t *testing.T, reply func(dnsmessage.Message) dnsmessage.Message) netip.AddrPort {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxQueryBytes)
		for {
			count, remote, err := listener.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:count]) != nil {
				continue
			}
			response := reply(query)
			response.ID, response.Response, response.Questions = query.ID, true, query.Questions
			if payload, err := response.Pack(); err == nil {
				_, _ = listener.WriteToUDPAddrPort(payload, remote)
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	address, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listener address %T", listener.LocalAddr())
	}
	return address.AddrPort()
}

func mustName(t *testing.T, name string) dnsmessage.Name {
	t.Helper()
	parsed, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func aRecord(t *testing.T, owner, address string, ttl uint32) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: mustName(t, owner), Type: dnsmessage.TypeA,
			Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.AResource{A: netip.MustParseAddr(address).As4()},
	}
}

func cnameRecord(t *testing.T, owner, target string, ttl uint32) dnsmessage.Resource {
	t.Helper()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: mustName(t, owner), Type: dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: mustName(t, target)},
	}
}

// answerSummary lists each answer as "owner TYPE target-or-address".
func answerSummary(message dnsmessage.Message) []string {
	summary := make([]string, 0, len(message.Answers))
	for _, answer := range message.Answers {
		line := canonicalOwner(answer.Header.Name) + " " + strings.TrimPrefix(answer.Header.Type.String(), "Type")
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			line += " " + netip.AddrFrom4(body.A).String()
		case *dnsmessage.CNAMEResource:
			line += " " + canonicalOwner(body.CNAME)
		case *dnsmessage.MXResource:
			line += " " + canonicalOwner(body.MX)
		}
		summary = append(summary, line)
	}
	return summary
}

// namesPlan: zone corp.lan answers NXDOMAIN (git, build.dev, the CNAMEs
// wiki -> git, docs -> wiki, help -> support.example.com, a <-> b); zone
// corp.com leaves its other names to the host and holds www.
func namesPlan(t *testing.T, network ...netip.AddrPort) (Plan, *resolverEngine) {
	t.Helper()
	snapshot := dnsSnapshot()
	snapshot.DNS.Routes = append(snapshot.DNS.Routes,
		networkmap.DNSRoute{Suffix: "corp.lan", Resolvers: []networkmap.DNSResolver{}},
		networkmap.DNSRoute{Suffix: "corp.com", Unavailable: true, FailOpen: true})
	cname := func(name, target string) networkmap.DNSRecord {
		return networkmap.DNSRecord{Name: name, Type: networkmap.DNSRecordCNAME, Target: target}
	}
	snapshot.DNS.Records = append(snapshot.DNS.Records,
		networkRecord("git.corp.lan", netip.MustParseAddr("10.0.5.20")),
		networkRecord("build.dev.corp.lan", netip.MustParseAddr("10.0.5.21")),
		networkRecord("www.corp.com", netip.MustParseAddr("192.0.2.80")),
		cname("wiki.corp.lan", "git.corp.lan"), cname("docs.corp.lan", "wiki.corp.lan"),
		cname("help.corp.lan", "support.example.com"),
		cname("a.corp.lan", "b.corp.lan"), cname("b.corp.lan", "a.corp.lan"))
	plan, err := Compile(snapshot)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return plan, zoneEngine(t, network...)
}

func TestCompileDNSNames(t *testing.T) {
	t.Parallel()
	plan, _ := namesPlan(t)
	if hasRouteSuffix(plan.Routes, "git.corp.lan") || hasRouteSuffix(plan.Routes, "wiki.corp.lan") ||
		hasRouteSuffix(plan.Routes, "corp.com") {
		t.Fatalf("names of a routed zone got routes: %#v", plan.Routes)
	}
	www, found := mostSpecificRoute(plan.Routes, "www.corp.com")
	if !found || www.Suffix != "www.corp.com" || !www.Unavailable || !www.FailOpen || len(www.Resolvers) != 0 {
		t.Fatalf("the name of a host zone = %#v, %t", www, found)
	}
	// The mesh zone of dnsSnapshot holds names too.
	if !slices.Equal(plan.Interior, []string{"corp.lan", "dev.corp.lan", "example.mesh"}) {
		t.Fatalf("interior = %v", plan.Interior)
	}
	if len(plan.Aliases) != 5 || plan.Aliases[0].Name != "a.corp.lan" || plan.Aliases[4].Name != "wiki.corp.lan" {
		t.Fatalf("aliases = %v", plan.Aliases)
	}
	if cloned := clonePlan(plan); !slices.Equal(cloned.Aliases, plan.Aliases) ||
		!slices.Equal(cloned.Interior, plan.Interior) {
		t.Fatal("a cloned plan loses names")
	}
}

func TestResolverEngineAnswersLocalNames(t *testing.T) {
	t.Parallel()
	plan, engine := namesPlan(t)
	// A CNAME chain the node holds, answered with every step.
	docs := resolveName(t, engine, plan, "docs.corp.lan.", dnsmessage.TypeA)
	if !docs.Authoritative || docs.RCode != dnsmessage.RCodeSuccess || !slices.Equal(answerSummary(docs),
		[]string{"docs.corp.lan CNAME wiki.corp.lan", "wiki.corp.lan CNAME git.corp.lan", "git.corp.lan A 10.0.5.20"}) {
		t.Fatalf("docs = %v %v", docs.RCode, answerSummary(docs))
	}
	if cname := resolveName(t, engine, plan, "wiki.corp.lan.", dnsmessage.TypeCNAME); !slices.Equal(answerSummary(cname),
		[]string{"wiki.corp.lan CNAME git.corp.lan"}) {
		t.Fatalf("CNAME question = %v", answerSummary(cname))
	}
	// An interior name exists; an unknown one does not; a loop fails.
	for name, want := range map[string]dnsmessage.RCode{
		"dev.corp.lan.": dnsmessage.RCodeSuccess, "corp.lan.": dnsmessage.RCodeSuccess,
		"nope.corp.lan.": dnsmessage.RCodeNameError, "a.corp.lan.": dnsmessage.RCodeServerFailure,
	} {
		if message := resolveName(t, engine, plan, name, dnsmessage.TypeA); message.RCode != want ||
			(want != dnsmessage.RCodeServerFailure && len(message.Answers) != 0) {
			t.Errorf("%s = %v %v, want %v", name, message.RCode, answerSummary(message), want)
		}
	}
	// HTTPS of a name set in a host zone has no data: no public hint.
	if https := resolveName(t, engine, plan, "www.corp.com.", typeHTTPS); https.RCode != dnsmessage.RCodeSuccess ||
		len(https.Answers) != 0 {
		t.Fatalf("HTTPS = %v %v", https.RCode, answerSummary(https))
	}
}

func TestResolverEngineFollowsACNAMEOutside(t *testing.T) {
	t.Parallel()
	network := startScriptedUpstream(t, func(query dnsmessage.Message) dnsmessage.Message {
		reply := dnsmessage.Message{}
		switch canonicalOwner(query.Questions[0].Name) {
		case "support.example.com":
			reply.Answers = []dnsmessage.Resource{
				cnameRecord(t, "support.example.com.", "edge.cdn.example.net.", 300),
				aRecord(t, "edge.cdn.example.net.", "203.0.113.5", 300),
				aRecord(t, "unrelated.example.org.", "203.0.113.99", 300),
			}
			reply.Authorities = []dnsmessage.Resource{aRecord(t, "ns.example.com.", "203.0.113.53", 300)}
		case "poison.example.com":
			// A chain into a name the node holds, with a record for it.
			reply.Answers = []dnsmessage.Resource{
				cnameRecord(t, "poison.example.com.", "git.corp.lan.", 300),
				aRecord(t, "git.corp.lan.", "198.51.100.66", 300),
			}
		}
		return reply
	})
	plan, engine := namesPlan(t, network)
	help := resolveName(t, engine, plan, "help.corp.lan.", dnsmessage.TypeA)
	if help.Authoritative || len(help.Authorities) != 0 || !slices.Equal(answerSummary(help), []string{
		"help.corp.lan CNAME support.example.com", "support.example.com CNAME edge.cdn.example.net",
		"edge.cdn.example.net A 203.0.113.5",
	}) {
		t.Fatalf("help = %v, %d authorities", answerSummary(help), len(help.Authorities))
	}
	for _, answer := range help.Answers {
		if answer.Header.TTL > cappedTTL {
			t.Fatalf("a TTL of %d outlives a change", answer.Header.TTL)
		}
	}
	// An answer from outside never speaks for a name the node holds.
	plan.DefaultResolvers = []netip.AddrPort{network}
	poison := resolveName(t, engine, plan, "poison.example.com.", dnsmessage.TypeA)
	if !slices.Equal(answerSummary(poison), []string{
		"poison.example.com CNAME git.corp.lan",
		"git.corp.lan A 10.0.5.20",
	}) {
		t.Fatalf("poison = %v", answerSummary(poison))
	}
}

// A type the node does not hold for a name of a host zone comes from the
// host's DNS, cleaned: no CNAME of the name, and NXDOMAIN becomes no data.
func TestResolverEnginePassesOtherTypesThrough(t *testing.T) {
	t.Parallel()
	network := startScriptedUpstream(t, func(query dnsmessage.Message) dnsmessage.Message {
		question := query.Questions[0]
		if question.Type == dnsmessage.TypeTXT {
			return dnsmessage.Message{Header: dnsmessage.Header{RCode: dnsmessage.RCodeNameError}}
		}
		return dnsmessage.Message{Answers: []dnsmessage.Resource{
			cnameRecord(t, "www.corp.com.", "corp.github.io.", 300),
			{
				Header: dnsmessage.ResourceHeader{
					Name: question.Name, Type: dnsmessage.TypeMX,
					Class: dnsmessage.ClassINET, TTL: 300,
				},
				Body: &dnsmessage.MXResource{Pref: 10, MX: mustName(t, "mx.corp.com.")},
			},
		}}
	})
	plan, engine := namesPlan(t, network)
	mx := resolveName(t, engine, plan, "www.corp.com.", dnsmessage.TypeMX)
	if !slices.Equal(answerSummary(mx), []string{"www.corp.com MX mx.corp.com"}) {
		t.Fatalf("MX = %v", answerSummary(mx))
	}
	if txt := resolveName(t, engine, plan, "www.corp.com.", dnsmessage.TypeTXT); txt.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("TXT of a name the node holds = %v", txt.RCode)
	}
	if a := resolveName(t, engine, plan, "www.corp.com.", dnsmessage.TypeA); firstA(t, a) !=
		netip.MustParseAddr("192.0.2.80") {
		t.Fatalf("A = %v", answerSummary(a))
	}
}

// FuzzSanitizeAnswer: whatever an answer from outside holds, cleaning it
// never fails open: it parses or is refused, and the address of a name the
// node holds is always the node's own.
func FuzzSanitizeAnswer(f *testing.F) {
	question := dnsmessage.Question{
		Name: dnsmessage.MustNewName("poison.example.com."), Type: dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	seed := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: question.Name, Type: dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET, TTL: 60,
				},
				Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("git.corp.lan.")},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("git.corp.lan."), Type: dnsmessage.TypeA,
					Class: dnsmessage.ClassINET, TTL: 60,
				},
				Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 66}},
			},
		},
	}
	packed, err := seed.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(packed)
	plan := Plan{
		Routes:  []Route{{Suffix: "corp.lan", Resolvers: []netip.AddrPort{}}},
		Hosts:   []Host{{Name: "git.corp.lan", Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.20")}}},
		Aliases: []Alias{{Name: "wiki.corp.lan", Target: "git.corp.lan"}},
	}
	f.Fuzz(func(t *testing.T, response []byte) {
		cleaned, err := sanitizeAnswer(plan, question, response)
		if err != nil {
			return
		}
		var message dnsmessage.Message
		if message.Unpack(cleaned) != nil {
			if !slices.Equal(cleaned, response) {
				t.Fatal("cleaning produced an answer that does not parse")
			}
			return
		}
		for _, answer := range message.Answers {
			body, ok := answer.Body.(*dnsmessage.AResource)
			if ok && canonicalOwner(answer.Header.Name) == "git.corp.lan" &&
				netip.AddrFrom4(body.A) != netip.MustParseAddr("10.0.5.20") {
				t.Fatalf("an answer from outside spoke for git.corp.lan: %v", netip.AddrFrom4(body.A))
			}
		}
	})
}

// A zone that leaves its other names to the host keeps a route of its own,
// unavailable and failing open, when it is searched, lies under another
// route, or holds more names than the host can route one by one: its other
// names then reach the host's network resolvers, never SERVFAIL or
// NXDOMAIN.
func TestCompileKeepsAHostZoneRouteWhenItMustRoute(t *testing.T) {
	t.Parallel()
	network := startUDPUpstream(t, netip.MustParseAddr("192.0.2.99"))
	build := func(t *testing.T, change func(*networkmap.Snapshot)) Plan {
		t.Helper()
		snapshot := dnsSnapshot()
		snapshot.DNS.Routes = append(snapshot.DNS.Routes,
			networkmap.DNSRoute{Suffix: "corp.lan", Resolvers: []networkmap.DNSResolver{}},
			networkmap.DNSRoute{Suffix: "corp.com", Unavailable: true, FailOpen: true})
		snapshot.DNS.Records = append(snapshot.DNS.Records,
			networkRecord("www.corp.com", netip.MustParseAddr("192.0.2.80")))
		change(&snapshot)
		plan, err := Compile(snapshot)
		if err != nil {
			t.Fatalf("Compile() error = %v", err)
		}
		return plan
	}
	searched := build(t, func(snapshot *networkmap.Snapshot) {
		snapshot.DNS.SearchDomains = append(snapshot.DNS.SearchDomains, "corp.com")
	})
	route, found := mostSpecificRoute(searched.Routes, "other.corp.com")
	if !found || route.Suffix != "corp.com" || !route.hostZone() || hasRouteSuffix(searched.Routes, "www.corp.com") {
		t.Fatalf("searched host zone routes = %#v", searched.Routes)
	}
	if got := firstA(t, resolveName(t, zoneEngine(t, network), searched, "other.corp.com.",
		dnsmessage.TypeA)); got != netip.MustParseAddr("192.0.2.99") {
		t.Fatalf("another name of a searched host zone got %s", got)
	}
	many := build(t, func(snapshot *networkmap.Snapshot) {
		for index := range maxNameRoutedDomains {
			snapshot.DNS.Records = append(snapshot.DNS.Records, networkRecord(
				"n"+strconv.Itoa(index)+".corp.com", netip.AddrFrom4([4]byte{10, 1, byte(index >> 8), byte(index)}),
			))
		}
	})
	if len(many.Routes) > maxNameRoutedDomains || !hasRouteSuffix(many.Routes, "corp.com") {
		t.Fatalf("a host zone of %d names routes %d domains", maxNameRoutedDomains+1, len(many.Routes))
	}
	nested := build(t, func(snapshot *networkmap.Snapshot) {
		snapshot.DNS.Routes = append(snapshot.DNS.Routes,
			networkmap.DNSRoute{Suffix: "dev.corp.lan", Unavailable: true, FailOpen: true})
		snapshot.DNS.Records = append(snapshot.DNS.Records,
			networkRecord("git.dev.corp.lan", netip.MustParseAddr("10.0.6.1")))
	})
	if route, found := mostSpecificRoute(nested.Routes, "other.dev.corp.lan"); !found ||
		route.Suffix != "dev.corp.lan" || route.local() {
		t.Fatalf("a host zone under an nxdomain zone = %#v", nested.Routes)
	}
}

func TestInternetSuffix(t *testing.T) {
	t.Parallel()
	for suffix, want := range map[string]bool{
		".": true, "com": true, "co.uk": true, "ck": true, "arpa": true,
		"lan": false, "corp": false, "corp.com": false, "home.arpa": false, "x.home.arpa": false,
	} {
		if got := internetSuffix(suffix); got != want {
			t.Errorf("internetSuffix(%q) = %t, want %t", suffix, got, want)
		}
	}
}

// An answer whose authority or additional section speaks for a name the
// node holds is rewritten: those sections go.
func TestSanitizeAnswerDropsSectionsAboutHeldNames(t *testing.T) {
	t.Parallel()
	plan, _ := namesPlan(t)
	question := dnsmessage.Question{
		Name: mustName(t, "evil.example."), Type: dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	packed, err := (&dnsmessage.Message{
		Header:      dnsmessage.Header{Response: true},
		Questions:   []dnsmessage.Question{question},
		Answers:     []dnsmessage.Resource{aRecord(t, "evil.example.", "203.0.113.7", 60)},
		Authorities: []dnsmessage.Resource{aRecord(t, "git.corp.lan.", "198.51.100.66", 86400)},
		Additionals: []dnsmessage.Resource{aRecord(t, "www.corp.com.", "198.51.100.66", 86400)},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := sanitizeAnswer(plan, question, packed)
	if err != nil {
		t.Fatal(err)
	}
	message := unpackMessage(t, cleaned)
	if len(message.Authorities) != 0 || len(message.Additionals) != 0 ||
		!slices.Equal(answerSummary(message), []string{"evil.example A 203.0.113.7"}) {
		t.Fatalf("cleaned = %v, %d authorities, %d additionals", answerSummary(message), len(message.Authorities),
			len(message.Additionals))
	}
}
