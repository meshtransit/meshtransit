package dnsconfig

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNS names an administrator sets (DNS design D2 §5): the node answers the
// names it holds, follows CNAMEs, and never lets an answer from outside
// speak for a name it holds.

// Question types without a constant in dnsmessage.
const (
	typeSVCB  dnsmessage.Type = 64
	typeHTTPS dnsmessage.Type = 65
	typeDNAME dnsmessage.Type = 39
)

// maxCNAMEChain bounds the CNAMEs one answer follows, the node's and the
// ones from outside together.
const maxCNAMEChain = 8

var errCNAMEChain = errors.New("dnsconfig: CNAME chain loops or is too long")

// cappedTTL is the most any answer about a name the node holds may be kept.
var cappedTTL = uint32(positiveTTL / time.Second)

func findAlias(aliases []Alias, name string) (Alias, bool) {
	index, found := slices.BinarySearchFunc(aliases, name, func(alias Alias, target string) int {
		return strings.Compare(alias.Name, target)
	})
	if !found {
		return Alias{}, false
	}
	return aliases[index], true
}

func isInterior(plan Plan, name string) bool {
	_, found := slices.BinarySearch(plan.Interior, name)
	return found
}

// holds reports a name the node answers itself: one of its names (an
// address name or a CNAME), an interior name, or one under a route it
// answers itself (the mesh names, a zone that answers NXDOMAIN).
func holds(plan Plan, name string) bool {
	if _, found := findHost(plan.Hosts, name); found {
		return true
	}
	if _, found := findAlias(plan.Aliases, name); found {
		return true
	}
	if isInterior(plan, name) {
		return true
	}
	route, routed := mostSpecificRoute(plan.Routes, name)
	return routed && route.local()
}

// passesThrough returns the route that answers a type the node does not
// hold for one of its address names, in a zone that is not the node's own
// (DNS design D2 §5.1, Q3): MX, TXT and the like then come from the zone's
// resolvers, or the host's DNS, so mail of a domain on the Internet keeps
// working when a name of it is set. Addresses, HTTPS and SVCB (no data, so
// a browser takes no hint past the name set) and CNAME stay the node's.
func passesThrough(plan Plan, name string, question dnsmessage.Type) (Route, bool) {
	switch question {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeALL, dnsmessage.TypeCNAME, typeSVCB, typeHTTPS:
		return Route{}, false
	}
	route, routed := mostSpecificRoute(plan.Routes, name)
	return route, routed && !route.local()
}

func canonicalOwner(name dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(name.String(), "."))
}

func cnameResource(owner, target string) (dnsmessage.Resource, error) {
	ownerName, err := dnsName(owner)
	if err != nil {
		return dnsmessage.Resource{}, err
	}
	targetName, err := dnsName(target)
	if err != nil {
		return dnsmessage.Resource{}, err
	}
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: ownerName, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET,
			TTL: cappedTTL,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: targetName},
	}, nil
}

// addressResources are host's records of the question type, owned by
// owner.
func addressResources(host Host, owner string, question dnsmessage.Type) ([]dnsmessage.Resource, error) {
	ownerName, err := dnsName(owner)
	if err != nil {
		return nil, err
	}
	var resources []dnsmessage.Resource
	for _, address := range host.Addresses {
		header := dnsmessage.ResourceHeader{Name: ownerName, Class: dnsmessage.ClassINET, TTL: cappedTTL}
		switch {
		case address.Is4() && (question == dnsmessage.TypeA || question == dnsmessage.TypeALL):
			header.Type = dnsmessage.TypeA
			resources = append(resources, dnsmessage.Resource{
				Header: header,
				Body:   &dnsmessage.AResource{A: address.As4()},
			})
		case address.Is6() && (question == dnsmessage.TypeAAAA || question == dnsmessage.TypeALL):
			header.Type = dnsmessage.TypeAAAA
			resources = append(resources, dnsmessage.Resource{
				Header: header,
				Body:   &dnsmessage.AAAAResource{AAAA: address.As16()},
			})
		}
	}
	return resources, nil
}

// localChain answers name from the node alone: its CNAMEs, then its
// addresses; no data for an interior name or a type it does not hold;
// NXDOMAIN for a name under a route it answers itself that it does not
// hold. When the chain leaves the node's names, left is where: the answer
// so far is the chain to it.
func localChain(plan Plan, name string, question dnsmessage.Type, steps *int) (
	chain []dnsmessage.Resource, rcode dnsmessage.RCode, left string, err error,
) {
	current := name
	for {
		alias, found := findAlias(plan.Aliases, current)
		if !found {
			break
		}
		if *steps == maxCNAMEChain {
			return nil, 0, "", errCNAMEChain
		}
		*steps++
		resource, err := cnameResource(current, alias.Target)
		if err != nil {
			return nil, 0, "", err
		}
		chain = append(chain, resource)
		current = alias.Target
	}
	if host, found := findHost(plan.Hosts, current); found {
		addresses, err := addressResources(host, current, question)
		return append(chain, addresses...), dnsmessage.RCodeSuccess, "", err
	}
	if !holds(plan, current) {
		return chain, dnsmessage.RCodeSuccess, current, nil
	}
	if isInterior(plan, current) {
		return chain, dnsmessage.RCodeSuccess, "", nil
	}
	return chain, dnsmessage.RCodeNameError, "", nil
}

// walkUpstream takes from an answer from outside only the chain that starts
// at name (DNS design D2 §5.4): CNAMEs, then the records of the question
// type of the name the chain ends at. It never takes a record a name the
// node holds owns: the chain stops there, and held is that name, which the
// node answers itself. DNAMEs, signatures and every other record are
// dropped.
func walkUpstream(plan Plan, answers []dnsmessage.Resource, name string, question dnsmessage.Type,
	steps *int,
) (chain []dnsmessage.Resource, held string, err error) {
	current := name
	for {
		if current != name && holds(plan, current) {
			return chain, current, nil
		}
		next := ""
		for _, resource := range answers {
			if resource.Header.Type != dnsmessage.TypeCNAME || canonicalOwner(resource.Header.Name) != current {
				continue
			}
			body, ok := resource.Body.(*dnsmessage.CNAMEResource)
			if !ok {
				continue
			}
			next = canonicalOwner(body.CNAME)
			chain = append(chain, resource)
			break
		}
		if next == "" {
			break
		}
		if *steps == maxCNAMEChain {
			return nil, "", errCNAMEChain
		}
		*steps++
		current = next
	}
	for _, resource := range answers {
		if canonicalOwner(resource.Header.Name) != current {
			continue
		}
		switch resource.Header.Type {
		case dnsmessage.TypeCNAME, typeDNAME, dnsmessage.Type(46), dnsmessage.Type(47), dnsmessage.Type(50),
			dnsmessage.TypeOPT:
			continue
		}
		if question == dnsmessage.TypeALL || resource.Header.Type == question {
			chain = append(chain, resource)
		}
	}
	return chain, "", nil
}

// capTTL bounds every record's TTL: an answer that touches the node's names
// never outlives a change of them.
func capTTL(resources []dnsmessage.Resource) {
	for index := range resources {
		resources[index].Header.TTL = min(resources[index].Header.TTL, cappedTTL)
	}
}

// sanitizeAnswer rewrites an answer from outside that touches a name the
// node holds (DNS design D2 §5.4); one that does not is returned as is. For
// a name the node holds (a type it passed through), only that name's
// records of the question type stay, and NXDOMAIN becomes no data: the name
// exists. Otherwise the chain from the name stays, cut at the first name
// the node holds, which the node answers itself. Authority and additional
// records go, the answer is no longer authenticated, and every TTL is at
// most 5 seconds.
func sanitizeAnswer(plan Plan, question dnsmessage.Question, response []byte) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing upstream answer: %w", err)
	}
	name := canonicalOwner(question.Name)
	nameHeld := holds(plan, name)
	touches := nameHeld
	// Every section: a cache may keep an authority or additional record too.
	for _, resource := range slices.Concat(message.Answers, message.Authorities, message.Additionals) {
		if touches {
			break
		}
		if resource.Header.Type == dnsmessage.TypeOPT {
			continue
		}
		touches = resource.Header.Type == typeDNAME || holds(plan, canonicalOwner(resource.Header.Name))
		if body, ok := resource.Body.(*dnsmessage.CNAMEResource); ok && !touches {
			touches = holds(plan, canonicalOwner(body.CNAME))
		}
	}
	if !touches {
		return response, nil
	}
	var answers []dnsmessage.Resource
	switch {
	case nameHeld:
		for _, resource := range message.Answers {
			if canonicalOwner(resource.Header.Name) == name && resource.Header.Type == question.Type {
				answers = append(answers, resource)
			}
		}
		if message.RCode == dnsmessage.RCodeNameError {
			message.RCode = dnsmessage.RCodeSuccess
		}
	default:
		steps := 0
		chain, held, err := walkUpstream(plan, message.Answers, name, question.Type, &steps)
		if err != nil {
			return nil, err
		}
		answers = chain
		if held != "" {
			local, rcode, _, err := localChain(plan, held, question.Type, &steps)
			if err != nil {
				return nil, err
			}
			answers, message.RCode = append(answers, local...), rcode
		}
	}
	capTTL(answers)
	message.Answers = answers
	message.Authorities = nil
	message.Additionals = slices.DeleteFunc(message.Additionals, func(resource dnsmessage.Resource) bool {
		return resource.Header.Type != dnsmessage.TypeOPT
	})
	message.AuthenticData = false
	return message.Pack()
}

// aliasQuery is one question for a name the node holds as a CNAME.
type aliasQuery struct {
	plan      Plan
	query     []byte
	message   dnsmessage.Message
	question  dnsmessage.Question
	name      string
	transport string
}

// resolveAlias answers a name the node holds as a CNAME (DNS design D2
// §5.3): the CNAME itself for a CNAME question, otherwise the whole chain
// and the records of the question type at its end. A chain that leaves the
// node's names is asked of the resolvers that name would go to (a zone's,
// the exit node's forwarder, the host's network), in one forward slot and
// one budget, and its answer is taken as walkUpstream allows.
func (e *resolverEngine) resolveAlias(ctx context.Context, alias aliasQuery) ([]byte, error) {
	response := baseResponse(alias.message, alias.plan)
	fail := func(cause error) ([]byte, error) {
		return e.failure(alias.query, alias.message, alias.question, alias.plan, alias.transport,
			authoritativeZone(alias.plan.Routes, alias.name), cause)
	}
	if alias.question.Type == dnsmessage.TypeCNAME {
		target, _ := findAlias(alias.plan.Aliases, alias.name)
		resource, err := cnameResource(alias.name, target.Target)
		if err != nil {
			return nil, err
		}
		response.Authoritative, response.Answers = true, []dnsmessage.Resource{resource}
		packed, err := response.Pack()
		if err != nil {
			return nil, err
		}
		return limitUDPResponse(alias.query, packed, alias.transport)
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	steps, slot, external := 0, false, false
	defer func() {
		if slot {
			<-e.forwardSlots
		}
	}()
	current, rcode := alias.name, dnsmessage.RCodeSuccess
	for {
		chain, localRCode, left, err := localChain(alias.plan, current, alias.question.Type, &steps)
		if err != nil {
			return fail(err)
		}
		response.Answers, rcode = append(response.Answers, chain...), localRCode
		if left == "" {
			break
		}
		if !slot {
			select {
			case e.forwardSlots <- struct{}{}:
				slot = true
			default:
				return fail(errForwardBusy)
			}
		}
		external = true
		answer, err := e.askOutside(ctx, alias.plan, left, alias.question.Type, alias.transport)
		if err != nil {
			return fail(err)
		}
		if answer == nil {
			break // no data: the exit node carries no IPv6
		}
		upstream, held, err := walkUpstream(alias.plan, answer.Answers, left, alias.question.Type, &steps)
		if err != nil {
			return fail(err)
		}
		response.Answers, rcode = append(response.Answers, upstream...), answer.RCode
		if held == "" {
			break
		}
		current = held
	}
	if e.failuresAsNXDOMAIN && failureRCode(rcode) {
		return fail(upstreamRCodeError{rcode: rcode})
	}
	capTTL(response.Answers)
	response.RCode = rcode
	response.Authoritative = !external
	if !external && (rcode == dnsmessage.RCodeNameError || len(response.Answers) == 0 ||
		response.Answers[len(response.Answers)-1].Header.Type == dnsmessage.TypeCNAME) {
		last := alias.name
		if count := len(response.Answers); count > 0 {
			if body, ok := response.Answers[count-1].Body.(*dnsmessage.CNAMEResource); ok {
				last = canonicalOwner(body.CNAME)
			}
		}
		if err := appendSOA(&response, authoritativeZone(alias.plan.Routes, last)); err != nil {
			return nil, err
		}
	}
	packed, err := response.Pack()
	if err != nil {
		return nil, err
	}
	return limitUDPResponse(alias.query, packed, alias.transport)
}

// askOutside asks the question for name of the resolvers it would go to on
// its own: a zone's (then, for a zone that fails open, the host's), or with
// no route the exit node's forwarder while one is in use, else the
// Network's resolvers, else the host's network. nil, nil is no data.
func (e *resolverEngine) askOutside(ctx context.Context, plan Plan, name string, questionType dnsmessage.Type,
	transport string,
) (*dnsmessage.Message, error) {
	questionName, err := dnsName(name)
	if err != nil {
		return nil, err
	}
	question := dnsmessage.Question{Name: questionName, Type: questionType, Class: dnsmessage.ClassINET}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("dnsconfig: generating chase transaction id: %w", err)
	}
	// EDNS0, so a chain's answer fits over UDP without losing its end.
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(maxUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, fmt.Errorf("dnsconfig: building chase EDNS0: %w", err)
	}
	query, err := (&dnsmessage.Message{
		Header:      dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
		Questions:   []dnsmessage.Question{question},
		Additionals: []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}},
	}).Pack()
	if err != nil {
		return nil, fmt.Errorf("dnsconfig: building chase query: %w", err)
	}
	var targets, fallback []netip.AddrPort
	var gate trialGate
	route, routed := mostSpecificRoute(plan.Routes, name)
	infrastructure := !routed && plan.Root != nil && e.infrastructureName(name)
	if !routed && plan.Root != nil && !infrastructure {
		// A name no route holds is the root zone's (DNS design D1b §5.1),
		// failing open in a captive portal window (Q6).
		route, routed = *plan.Root, true
		if (plan.Exit != nil || e.exitPending(plan)) && len(e.captiveResolvers()) != 0 {
			route.FailOpen = true
		}
	}
	switch {
	case infrastructure:
		// MeshTransit's own names stay beside the root zone (§5.8).
		var noData bool
		if targets, _, noData = e.failOpenTargets(plan, question); noData {
			return nil, nil
		}
	case routed:
		var noData bool
		targets, _, noData = e.zoneTargets(plan, route, question)
		if noData {
			return nil, nil
		}
		targets = e.byLiveness(targets, route.Resolvers)
		gate = zoneGate{breaker: e.breaker, own: route.Resolvers, health: e.health}
		if route.FailOpen {
			fallback, _, _ = e.failOpenTargets(plan, question)
		}
	case e.exitPending(plan):
		// No target: the chase fails.
	case plan.Exit != nil:
		if network := e.captiveResolvers(); len(network) != 0 {
			targets = network
		} else if questionType == dnsmessage.TypeAAAA && !plan.Exit.IPv6 {
			return nil, nil
		} else {
			targets = slices.Clone(plan.Exit.Resolvers)
		}
	case len(plan.DefaultResolvers) != 0:
		targets = slices.Clone(plan.DefaultResolvers)
	default:
		targets = e.networkTargets()
	}
	response, err := forwardQuery(ctx, query, question, targets, transport, gate)
	// A zone never fails open past a resolver that answered SERVFAIL or
	// REFUSED (DNS design D1b §5.3): the chase fails instead.
	if _, answered := upstreamAnswer(err); err != nil && !answered && len(fallback) != 0 && ctx.Err() == nil {
		response, err = forwardQuery(ctx, query, question, fallback, transport, nil)
	}
	if err != nil {
		return nil, err
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing chase answer: %w", err)
	}
	return &message, nil
}
