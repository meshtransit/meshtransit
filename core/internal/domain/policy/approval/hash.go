package approval

import (
	"crypto/sha256"
	"encoding/binary"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/identity/accountsession"
)

const (
	requestHashDomainV1  = "meshtransit/policy-approval-request/v1\x00"
	decisionHashDomainV1 = "meshtransit/policy-approval-decision/v1\x00"
)

// RequestHash is deterministic idempotency evidence for a proposal.
type RequestHash [sha256.Size]byte

// NewRequestHash validates a non-zero request digest loaded at a boundary.
func NewRequestHash(value [sha256.Size]byte) (RequestHash, error) {
	hash := RequestHash(value)
	if !hash.IsValid() {
		return RequestHash{}, ErrInvalidRequestCommand
	}
	return hash, nil
}

// Bytes returns a defensive digest copy.
func (hash RequestHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether request evidence is present.
func (hash RequestHash) IsValid() bool { return hash != RequestHash{} }

// DecisionHash is deterministic idempotency evidence for a human approval.
type DecisionHash [sha256.Size]byte

// NewDecisionHash validates a non-zero decision digest loaded at a boundary.
func NewDecisionHash(value [sha256.Size]byte) (DecisionHash, error) {
	hash := DecisionHash(value)
	if !hash.IsValid() {
		return DecisionHash{}, ErrInvalidApprovalCommand
	}
	return hash, nil
}

// Bytes returns a defensive digest copy.
func (hash DecisionHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether decision evidence is present.
func (hash DecisionHash) IsValid() bool { return hash != DecisionHash{} }

func appendText(output []byte, value string) []byte {
	output = appendUint64(output, uint64(len(value)))
	return append(output, value...)
}

func appendInt64(output []byte, value int64) []byte {
	encoded, err := binary.Append(output, binary.BigEndian, value)
	if err != nil {
		panic("policy approval: encode int64")
	}
	return encoded
}

func appendUint64(output []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(output, value)
}

func appendVector(output []byte, vector accessgraph.RevisionVector) []byte {
	for _, value := range [...]int64{
		vector.NetworkRevision(), vector.InventoryRevision(), vector.GroupRevision(),
		vector.PolicyRevision(), vector.DNSRevision(), vector.RouteRevision(),
		vector.SharingRevision(), vector.IsolationGeneration(),
	} {
		output = appendInt64(output, value)
	}
	return output
}

func appendBinding(output []byte, binding Binding) []byte {
	output = appendText(output, binding.Scope().WorkspaceID().String())
	output = appendText(output, binding.Scope().NetworkID().String())
	output = appendVector(output, binding.BaselineVector())
	output = appendVector(output, binding.ProposedVector())
	output = appendInt64(output, int64(binding.CompilerFormatVersion()))
	semanticHash := binding.CandidateSemanticHash().Bytes()
	output = append(output, semanticHash[:]...)
	impactHash := binding.ImpactHash().Bytes()
	return append(output, impactHash[:]...)
}

func appendSession(output []byte, session accountsession.Session) []byte {
	for _, value := range [...]string{
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
	} {
		output = appendText(output, value)
	}
	output = appendInt64(output, session.AuthenticationTime().UnixNano())
	for _, value := range [...]int64{
		session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
	} {
		output = appendInt64(output, value)
	}
	return output
}
