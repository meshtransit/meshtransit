package dnsconfig

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A diagnostic question (meshctl dns query, DNS design D5f): where the
// node's resolver sends a name, and what came back. It asks as an
// application would, so it touches the breaker and health as one does.

// QueryPath is where the resolver sends a name.
type QueryPath string

// The paths a name takes, in the order the resolver tries them.
const (
	PathMesh           QueryPath = "mesh"           // a name the map holds: Device, alias, share, record
	PathZoneLocal      QueryPath = "zone_local"     // a zone of names only: answered here
	PathZone           QueryPath = "zone"           // a forward zone's resolvers
	PathRootZone       QueryPath = "root_zone"      // the root zone's resolvers
	PathInfrastructure QueryPath = "infrastructure" // MeshTransit's own names beside the root zone
	PathExit           QueryPath = "exit"           // the exit node's forwarder
	PathNetwork        QueryPath = "network"        // the Network's default resolvers, or the network's
	PathHost           QueryPath = "host"           // the host's own DNS: MeshTransit does not take the name
	PathNone           QueryPath = "none"           // nothing may answer it (exit node chosen, not yet in use)
)

// QueryResolver is one resolver the question may go to, in order.
type QueryResolver struct {
	Address netip.AddrPort
	// ViaExit is a zone's Internet resolver asked through the exit node.
	ViaExit bool
	// Skipped is a resolver the breaker skips now.
	Skipped bool
}

// QueryReport is a diagnostic question's path and answer.
type QueryReport struct {
	Name      string
	Type      string
	Path      QueryPath
	Zone      string // the zone's domain, for a zone path
	FailOpen  bool
	Resolvers []QueryResolver
	RCode     string
	Answers   []string
	Elapsed   time.Duration
}

// ErrQueryName reports a diagnostic question whose name or type is not
// valid.
var ErrQueryName = errors.New("dnsconfig: the name or type is not valid")

// ErrQueryUnavailable reports a resolver that answers no diagnostic
// question.
var ErrQueryUnavailable = errors.New("dnsconfig: this resolver answers no diagnostic question")

// maxQueryNameBytes bounds a diagnostic name.
const maxQueryNameBytes = 253

// queryTypes are the types a diagnostic question asks.
var queryTypes = map[string]dnsmessage.Type{
	"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "CNAME": dnsmessage.TypeCNAME,
	"MX": dnsmessage.TypeMX, "NS": dnsmessage.TypeNS, "PTR": dnsmessage.TypePTR,
	"SOA": dnsmessage.TypeSOA, "SRV": dnsmessage.TypeSRV, "TXT": dnsmessage.TypeTXT,
	"HTTPS": dnsmessage.Type(65), "SVCB": dnsmessage.Type(64),
}

// query asks the resolver name of type typeName under plan and reports
// where it went and what came back.
func (e *resolverEngine) query(ctx context.Context, plan Plan, name, typeName string) (QueryReport, error) {
	typeName = strings.ToUpper(strings.TrimSpace(typeName))
	if typeName == "" {
		typeName = "A"
	}
	questionType, known := queryTypes[typeName]
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if !known || name == "" || len(name) > maxQueryNameBytes {
		return QueryReport{}, ErrQueryName
	}
	name = e.expandShortName(plan, name)
	questionName, err := dnsName(name)
	if err != nil {
		return QueryReport{}, ErrQueryName
	}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return QueryReport{}, fmt.Errorf("dnsconfig: query id: %w", err)
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(maxUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
		return QueryReport{}, fmt.Errorf("dnsconfig: query EDNS: %w", err)
	}
	message := dnsmessage.Message{
		Header:      dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions:   []dnsmessage.Question{{Name: questionName, Type: questionType, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}},
	}
	packed, err := message.Pack()
	if err != nil {
		return QueryReport{}, ErrQueryName
	}
	report := e.describe(plan, message, message.Questions[0], name)
	report.Name, report.Type = name, typeName
	if report.Path == PathHost {
		// The host never sends it here: what MeshTransit would answer
		// tells nothing.
		return report, nil
	}
	started := time.Now()
	response, err := e.resolve(ctx, plan, packed, "udp")
	report.Elapsed = time.Since(started)
	if len(response) == 0 {
		if err == nil {
			err = errNoResolver
		}
		return report, err
	}
	var answer dnsmessage.Message
	if err := answer.Unpack(response); err != nil {
		return report, fmt.Errorf("dnsconfig: reading the answer: %w", err)
	}
	report.RCode = rcodeName(answer.RCode)
	for _, resource := range answer.Answers {
		report.Answers = append(report.Answers, answerText(resource))
	}
	return report, nil
}

// expandShortName tries a name of one label under the search domains, as
// the host would: the first under which MeshTransit takes it, or the name.
func (e *resolverEngine) expandShortName(plan Plan, name string) string {
	if strings.Contains(name, ".") {
		return name
	}
	for _, domain := range plan.SearchDomains {
		candidate := name + "." + strings.TrimSuffix(domain, ".")
		questionName, err := dnsName(candidate)
		if err != nil {
			continue
		}
		question := dnsmessage.Question{Name: questionName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
		message := dnsmessage.Message{Questions: []dnsmessage.Question{question}}
		if e.describe(plan, message, question, candidate).Path != PathHost {
			return candidate
		}
	}
	return name
}

// describe tells where resolve sends question, without asking anyone.
func (e *resolverEngine) describe(plan Plan, message dnsmessage.Message, question dnsmessage.Question,
	name string,
) QueryReport {
	if _, own, _ := ownNameAnswer(plan, message, question, name); own {
		return QueryReport{Path: PathMesh}
	}
	if _, found := findHost(plan.Hosts, name); found {
		if route, pass := passesThrough(plan, name, question.Type); pass {
			return e.describeZone(plan, route, question, PathZone)
		}
		return QueryReport{Path: PathMesh}
	}
	if _, found := findAlias(plan.Aliases, name); found {
		return QueryReport{Path: PathMesh}
	}
	if route, routed := mostSpecificRoute(plan.Routes, name); routed {
		if route.local() {
			return QueryReport{Path: PathZoneLocal, Zone: route.Suffix}
		}
		return e.describeZone(plan, route, question, PathZone)
	}
	if plan.Root != nil {
		if e.infrastructureName(name) {
			targets, _, _ := e.failOpenTargets(plan, question)
			return QueryReport{Path: PathInfrastructure, Resolvers: e.describeResolvers(targets, nil, netip.AddrPort{})}
		}
		return e.describeZone(plan, *plan.Root, question, PathRootZone)
	}
	switch {
	case plan.Exit != nil:
		targets := plan.Exit.Resolvers
		if network := e.captiveResolvers(); len(network) != 0 {
			return QueryReport{Path: PathNetwork, Resolvers: e.describeResolvers(network, nil, netip.AddrPort{})}
		}
		return QueryReport{Path: PathExit, Resolvers: e.describeResolvers(targets, nil, netip.AddrPort{})}
	case e.exitPending(plan):
		return QueryReport{Path: PathNone}
	case len(plan.DefaultResolvers) != 0:
		return QueryReport{Path: PathNetwork, Resolvers: e.describeResolvers(plan.DefaultResolvers, nil, netip.AddrPort{})}
	case e.fullResolver:
		return QueryReport{Path: PathNetwork, Resolvers: e.describeResolvers(e.networkTargets(), nil, netip.AddrPort{})}
	default:
		return QueryReport{Path: PathHost}
	}
}

// describeZone tells which of a zone's resolvers question goes to.
func (e *resolverEngine) describeZone(plan Plan, route Route, question dnsmessage.Question, path QueryPath) QueryReport {
	targets, captiveWindow, _ := e.zoneTargets(plan, route, question)
	via := netip.AddrPort{}
	if !captiveWindow {
		via = e.relayVia(plan)
	}
	return QueryReport{
		Path: path, Zone: route.Suffix, FailOpen: route.FailOpen,
		Resolvers: e.describeResolvers(targets, route.Resolvers, via),
	}
}

// describeResolvers lists targets, marking those asked through the exit
// node and those of own the breaker skips now.
func (e *resolverEngine) describeResolvers(targets, own []netip.AddrPort, via netip.AddrPort) []QueryResolver {
	gate := e.zoneGate(own, via)
	described := make([]QueryResolver, 0, len(targets))
	for _, target := range targets {
		breaker, _ := gate.path(target)
		described = append(described, QueryResolver{
			Address: target, ViaExit: relayed(target, via) && zoneResolver(gate, target),
			Skipped: zoneResolver(gate, target) && breaker.open(target),
		})
	}
	return described
}

// rcodeName is an rcode as DNS tools name it.
func rcodeName(rcode dnsmessage.RCode) string {
	switch rcode {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

// answerText is one answer record as dig prints its data.
func answerText(resource dnsmessage.Resource) string {
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(body.A).String()
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(body.AAAA).String()
	case *dnsmessage.CNAMEResource:
		return "CNAME " + body.CNAME.String()
	case *dnsmessage.PTRResource:
		return "PTR " + body.PTR.String()
	case *dnsmessage.MXResource:
		return fmt.Sprintf("MX %d %s", body.Pref, body.MX.String())
	case *dnsmessage.NSResource:
		return "NS " + body.NS.String()
	case *dnsmessage.TXTResource:
		return "TXT " + strings.Join(body.TXT, " ")
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("SRV %d %d %d %s", body.Priority, body.Weight, body.Port, body.Target.String())
	default:
		return resource.Header.Type.String()
	}
}

// Query asks the resolver name of type typeName and reports its path and
// answer (meshctl dns query).
func (s *Server) Query(ctx context.Context, name, typeName string) (QueryReport, error) {
	if s == nil {
		return QueryReport{}, errNoResolver
	}
	return s.engine.query(ctx, *s.plan.Load(), name, typeName)
}

// Query asks the resolver name of type typeName and reports its path and
// answer (meshctl dns query).
func (r *PacketResolver) Query(ctx context.Context, name, typeName string) (QueryReport, error) {
	if r == nil {
		return QueryReport{}, errNoResolver
	}
	plan := r.plan.Load()
	if plan == nil {
		return QueryReport{}, ErrQueryUnavailable
	}
	return r.engine.query(ctx, *plan, name, typeName)
}

// Query asks the manager's resolver, when it answers diagnostic questions.
func (m *Manager) Query(ctx context.Context, name, typeName string) (QueryReport, error) {
	if m == nil {
		return QueryReport{}, ErrQueryUnavailable
	}
	m.mu.Lock()
	resolver := m.resolver
	m.mu.Unlock()
	querier, ok := resolver.(interface {
		Query(context.Context, string, string) (QueryReport, error)
	})
	if !ok {
		return QueryReport{}, ErrQueryUnavailable
	}
	return querier.Query(ctx, name, typeName)
}
