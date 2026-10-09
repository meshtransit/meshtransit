package policy

import (
	"errors"
	"slices"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

var (
	// ErrInvalidPacketRequest reports incomplete or ambiguous packet evidence.
	ErrInvalidPacketRequest = errors.New("policy: invalid packet request")
)

// PacketRequestParams contains one exact packet-authorization question.
type PacketRequestParams struct {
	Scope             network.Scope
	PolicyRevision    int64
	SourceNodeID      node.ID
	DestinationNodeID node.ID
	Protocol          Protocol
	DestinationPort   uint16
}

// PacketRequest is one immutable exact-revision packet-authorization question.
type PacketRequest struct {
	scope             network.Scope
	policyRevision    int64
	sourceNodeID      node.ID
	destinationNodeID node.ID
	protocol          Protocol
	destinationPort   uint16
}

// NewPacketRequest validates one exact packet-authorization question.
func NewPacketRequest(params PacketRequestParams) (PacketRequest, error) {
	if !validPacketRequestParams(params) {
		return PacketRequest{}, ErrInvalidPacketRequest
	}
	return PacketRequest{
		scope:             params.Scope,
		policyRevision:    params.PolicyRevision,
		sourceNodeID:      params.SourceNodeID,
		destinationNodeID: params.DestinationNodeID,
		protocol:          params.Protocol,
		destinationPort:   params.DestinationPort,
	}, nil
}

func (request PacketRequest) isValid() bool {
	return validPacketRequestParams(PacketRequestParams{
		Scope:             request.scope,
		PolicyRevision:    request.policyRevision,
		SourceNodeID:      request.sourceNodeID,
		DestinationNodeID: request.destinationNodeID,
		Protocol:          request.protocol,
		DestinationPort:   request.destinationPort,
	})
}

func validPacketRequestParams(params PacketRequestParams) bool {
	if !params.Scope.IsValid() || params.PolicyRevision <= 0 ||
		!params.SourceNodeID.IsValid() || !params.DestinationNodeID.IsValid() ||
		params.SourceNodeID == params.DestinationNodeID || !params.Protocol.IsValid() {
		return false
	}
	if params.Protocol == ProtocolICMP {
		return params.DestinationPort == 0
	}
	return params.DestinationPort > 0
}

// Reason is a stable, bounded packet-policy decision classification.
type Reason uint8

const (
	// ReasonUnknown is the invalid zero-value reason.
	ReasonUnknown Reason = iota
	// ReasonAllowed means at least one active exact rule matched.
	ReasonAllowed
	// ReasonInvalidInput means request or policy evidence was malformed.
	ReasonInvalidInput
	// ReasonScopeMismatch means the request targeted another Network.
	ReasonScopeMismatch
	// ReasonStalePolicy means the request did not bind the active policy revision.
	ReasonStalePolicy
	// ReasonNoMatchingRule means default deny applied.
	ReasonNoMatchingRule
)

// String returns the stable safe decision reason code.
func (reason Reason) String() string {
	switch reason {
	case ReasonAllowed:
		return "allowed"
	case ReasonInvalidInput:
		return "invalid_input"
	case ReasonScopeMismatch:
		return "scope_mismatch"
	case ReasonStalePolicy:
		return "stale_policy"
	case ReasonNoMatchingRule:
		return "no_matching_rule"
	default:
		return "unknown"
	}
}

// Decision is an immutable packet-policy outcome with deterministic evidence.
type Decision struct {
	reason  Reason
	ruleIDs []RuleID
}

// IsAllowed reports whether at least one exact rule matched the packet.
func (decision Decision) IsAllowed() bool { return decision.reason == ReasonAllowed }

// Reason returns the stable internal decision classification.
func (decision Decision) Reason() Reason { return decision.reason }

// RuleIDs returns caller-owned matching Access Rule identities.
func (decision Decision) RuleIDs() []RuleID { return slices.Clone(decision.ruleIDs) }

// Evaluate checks exact scope, revision, direction, protocol, and port against
// one immutable policy snapshot. Missing or ambiguous evidence denies.
func Evaluate(snapshot Snapshot, request PacketRequest) Decision {
	if !snapshot.IsValid() || !request.isValid() {
		return Decision{reason: ReasonInvalidInput, ruleIDs: []RuleID{}}
	}
	if snapshot.scope != request.scope {
		return Decision{reason: ReasonScopeMismatch, ruleIDs: []RuleID{}}
	}
	if snapshot.revision != request.policyRevision {
		return Decision{reason: ReasonStalePolicy, ruleIDs: []RuleID{}}
	}
	matching := make([]RuleID, 0, 1)
	for _, index := range snapshot.rulesFor(request.sourceNodeID, request.destinationNodeID) {
		rule := snapshot.rules[index]
		if rule.matches(request) {
			matching = append(matching, rule.id)
		}
	}
	if len(matching) == 0 {
		return Decision{reason: ReasonNoMatchingRule, ruleIDs: []RuleID{}}
	}
	return Decision{reason: ReasonAllowed, ruleIDs: matching}
}
