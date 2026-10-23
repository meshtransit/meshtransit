package dnsconfig

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A zone the node cannot resolve a name of answers SERVFAIL, or passes on a
// resolver's SERVFAIL or REFUSED (DNS design D1b §5.3). Some Android builds
// (MIUI) then ask Google's public DNS themselves, which skips a filtering
// resolver and a zone that fails closed; they keep an NXDOMAIN. With
// failuresAsNXDOMAIN (Android) such a failure is answered NXDOMAIN instead,
// carrying the reason as an Extended DNS Error (RFC 8914) when the question
// has EDNS (DNS design D1b §20).

// ednsOptionExtendedError is the EDNS option code of an Extended DNS Error.
const ednsOptionExtendedError = 15

// Extended DNS Error info codes (RFC 8914 §4).
const (
	edeOther                = 0
	edeProhibited           = 18
	edeNoReachableAuthority = 22
	edeInvalidData          = 24
)

// zoneFailure answers a name of zone the node could not resolve.
func (e *resolverEngine) zoneFailure(zone zoneQuery, cause error) ([]byte, error) {
	return e.failure(zone.query, zone.message, zone.question, zone.plan, zone.transport, zone.route.Suffix, cause)
}

// zoneAnswer passes on a resolver's answer for a name of zone. Where failures
// are answered as NXDOMAIN, an answer that fails (SERVFAIL, REFUSED, NOTIMP,
// FORMERR) or that cannot be taken is one too.
func (e *resolverEngine) zoneAnswer(zone zoneQuery, response []byte, captiveWindow bool) ([]byte, error) {
	if !e.failuresAsNXDOMAIN {
		return zone.answer(response, captiveWindow)
	}
	if rcode, ok := responseRCode(response); ok && failureRCode(rcode) {
		return e.zoneFailure(zone, upstreamRCodeError{rcode: rcode})
	}
	var err error
	if response, err = sanitizeAnswer(zone.plan, zone.question, response); err != nil {
		return e.zoneFailure(zone, rejectedAnswerError{err: err})
	}
	if captiveWindow {
		if response, err = capTTLs(response, uint32(positiveTTL/time.Second)); err != nil {
			return e.zoneFailure(zone, rejectedAnswerError{err: err})
		}
	}
	return limitUDPResponse(zone.query, response, zone.transport)
}

// upstreamRCodeError is a resolver's answer that failed with rcode, taken
// as the zone's.
type upstreamRCodeError struct{ rcode dnsmessage.RCode }

func (err upstreamRCodeError) Error() string {
	return "dnsconfig: upstream answered " + err.rcode.String()
}

// rejectedAnswerError is a resolver's answer the node could not take.
type rejectedAnswerError struct{ err error }

func (err rejectedAnswerError) Error() string { return err.err.Error() }

func (err rejectedAnswerError) Unwrap() error { return err.err }

// failureRCode reports an rcode some Android builds take as a reason to ask
// other DNS servers.
func failureRCode(rcode dnsmessage.RCode) bool {
	switch rcode {
	case dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused, dnsmessage.RCodeNotImplemented,
		dnsmessage.RCodeFormatError:
		return true
	default:
		return false
	}
}

func responseRCode(response []byte) (dnsmessage.RCode, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	return header.RCode, err == nil
}

// failure answers SERVFAIL, or NXDOMAIN with the reason where failures are
// answered as NXDOMAIN; suffix is the zone the negative answer speaks for.
// A failure no resolver answered (none reachable, the node busy) is not to
// be cached: its SOA says so, and the name resolves again as soon as a
// resolver answers.
func (e *resolverEngine) failure(query []byte, message dnsmessage.Message, question dnsmessage.Question,
	plan Plan, transport, suffix string, cause error,
) ([]byte, error) {
	if !e.failuresAsNXDOMAIN {
		return failureResponse(query, message, question, plan, transport, cause)
	}
	if suffix == "" {
		suffix = "."
	}
	code, text, answered := extendedError(cause)
	response, err := nxdomainResponse(message, question, plan, suffix, answered)
	if err == nil {
		response, err = limitUDPResponse(query, response, transport)
	}
	if err == nil {
		response, err = withExtendedError(response, code, text)
	}
	if err != nil {
		return failureResponse(query, message, question, plan, transport, errors.Join(cause, err))
	}
	if answered {
		// A resolver's answer, as it was before: not a failure of the node.
		return response, nil
	}
	return response, cause
}

// nxdomainResponse is NXDOMAIN under suffix's SOA; one not to be cached has
// its TTL and minimum at zero.
func nxdomainResponse(message dnsmessage.Message, question dnsmessage.Question, plan Plan, suffix string,
	cacheable bool,
) ([]byte, error) {
	response, err := negativeResponse(message, question, dnsmessage.RCodeNameError, suffix, plan)
	if err != nil || cacheable {
		return response, err
	}
	var parsed dnsmessage.Message
	if err := parsed.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing a negative answer: %w", err)
	}
	for index, authority := range parsed.Authorities {
		if soa, ok := authority.Body.(*dnsmessage.SOAResource); ok {
			parsed.Authorities[index].Header.TTL, soa.MinTTL = 0, 0
		}
	}
	return parsed.Pack()
}

// extendedError names why a name could not be resolved: a resolver refused
// it, a resolver failed, or none answered; answered is true when a
// resolver's answer says so.
func extendedError(cause error) (uint16, string, bool) {
	var failed upstreamRCodeError
	if errors.As(cause, &failed) {
		switch failed.rcode {
		case dnsmessage.RCodeRefused:
			return edeProhibited, "resolver refused", true
		case dnsmessage.RCodeFormatError:
			// Possibly the question's EDNS, not the name: not to be cached.
			return edeOther, "resolver failed", false
		default:
			return edeOther, "resolver failed", true
		}
	}
	var rejected rejectedAnswerError
	if errors.As(cause, &rejected) {
		return edeInvalidData, "answer rejected", false
	}
	if answered, ok := upstreamAnswer(cause); ok {
		if rcode, ok := responseRCode(answered); ok && rcode == dnsmessage.RCodeRefused {
			return edeProhibited, "resolver refused", true
		}
		return edeOther, "resolver failed", true
	}
	if errors.Is(cause, errForwardBusy) {
		return edeOther, "resolver busy", false
	}
	return edeNoReachableAuthority, "no resolver answered", false
}

// withExtendedError adds an Extended DNS Error to the OPT record of a
// response that has one; a response without EDNS, or truncated, is left as
// it is.
func withExtendedError(response []byte, code uint16, text string) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil {
		return nil, fmt.Errorf("dnsconfig: parsing response for an extended error: %w", err)
	}
	for index, additional := range message.Additionals {
		opt, ok := additional.Body.(*dnsmessage.OPTResource)
		if !ok || message.Truncated {
			continue
		}
		data := binary.BigEndian.AppendUint16(nil, code)
		data = append(data, text...)
		options := append(append([]dnsmessage.Option{}, opt.Options...),
			dnsmessage.Option{Code: ednsOptionExtendedError, Data: data})
		message.Additionals[index].Body = &dnsmessage.OPTResource{Options: options}
		packed, err := message.Pack()
		if err != nil {
			return nil, fmt.Errorf("dnsconfig: packing an extended error: %w", err)
		}
		return packed, nil
	}
	return response, nil
}
