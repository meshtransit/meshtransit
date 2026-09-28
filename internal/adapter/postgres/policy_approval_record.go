package postgres

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	approval "github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

type policyApprovalBindingRecord struct {
	baseline      [8]int64
	proposed      [8]int64
	candidateHash []byte
	compiler      int
	impactHash    []byte
}

func (record *policyApprovalBindingRecord) scanDestinations() []any {
	destinations := make([]any, 0, 19)
	for index := range record.baseline {
		destinations = append(destinations, &record.baseline[index])
	}
	for index := range record.proposed {
		destinations = append(destinations, &record.proposed[index])
	}
	return append(destinations, &record.candidateHash, &record.compiler, &record.impactHash)
}

func (record policyApprovalBindingRecord) binding(scope network.Scope) (approval.Binding, error) {
	baseline, err := policyApprovalRevisionVector(record.baseline)
	if err != nil {
		return approval.Binding{}, approval.ErrInvalidBinding
	}
	proposed, err := policyApprovalRevisionVector(record.proposed)
	if err != nil {
		return approval.Binding{}, approval.ErrInvalidBinding
	}
	candidateValue, err := policyApprovalDigest(record.candidateHash)
	if err != nil {
		return approval.Binding{}, approval.ErrInvalidBinding
	}
	candidate, err := publication.NewSemanticHash(candidateValue)
	if err != nil {
		return approval.Binding{}, approval.ErrInvalidBinding
	}
	impactValue, err := policyApprovalDigest(record.impactHash)
	if err != nil {
		return approval.Binding{}, approval.ErrInvalidBinding
	}
	impact, err := simulation.NewImpactHash(impactValue)
	if err != nil {
		return approval.Binding{}, approval.ErrInvalidBinding
	}
	return approval.NewBinding(approval.BindingParams{
		Scope: scope, BaselineVector: baseline, ProposedVector: proposed,
		CandidateSemanticHash: candidate, CompilerFormatVersion: record.compiler,
		ImpactHash: impact,
	})
}

func policyApprovalRevisionVector(values [8]int64) (accessgraph.RevisionVector, error) {
	return accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: values[0], InventoryRevision: values[1],
		GroupRevision: values[2], PolicyRevision: values[3],
		DNSRevision: values[4], RouteRevision: values[5],
		SharingRevision: values[6], IsolationGeneration: values[7],
	})
}

func policyApprovalDigest(value []byte) ([sha256.Size]byte, error) {
	if len(value) != sha256.Size {
		return [sha256.Size]byte{}, approval.ErrInvalidBinding
	}
	var digest [sha256.Size]byte
	copy(digest[:], value)
	if digest == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, approval.ErrInvalidBinding
	}
	return digest, nil
}

type policyApprovalRequestRecord struct {
	version           int64
	state             string
	proposerPrincipal string
	proposerSession   string
	binding           policyApprovalBindingRecord
	createdAt         time.Time
	expiresAt         time.Time
}

func scanLockedPolicyApprovalRequest(
	row policyApprovalRow,
) (policyApprovalRequestRecord, error) {
	var record policyApprovalRequestRecord
	destinations := []any{&record.version, &record.state, &record.proposerPrincipal, &record.proposerSession}
	destinations = append(destinations, record.binding.scanDestinations()...)
	destinations = append(destinations, &record.createdAt, &record.expiresAt)
	if err := row.Scan(destinations...); err != nil {
		return policyApprovalRequestRecord{}, err
	}
	return record, nil
}

func scanPolicyApprovalRequest(row policyApprovalRow) (policyApprovalRequestRecord, error) {
	var record policyApprovalRequestRecord
	destinations := []any{&record.proposerPrincipal, &record.proposerSession}
	destinations = append(destinations, record.binding.scanDestinations()...)
	destinations = append(destinations, &record.createdAt, &record.expiresAt)
	if err := row.Scan(destinations...); err != nil {
		return policyApprovalRequestRecord{}, err
	}
	record.version = 1
	record.state = approval.StatePending.String()
	return record, nil
}

func (record policyApprovalRequestRecord) result(
	scope network.Scope,
	requestID approval.RequestID,
) (approval.RequestResult, error) {
	binding, err := record.binding.binding(scope)
	if err != nil {
		return approval.RequestResult{}, err
	}
	principalID, principalErr := identity.ParsePrincipalID(record.proposerPrincipal)
	sessionID, sessionErr := accountsession.ParseID(record.proposerSession)
	if principalErr != nil || sessionErr != nil {
		return approval.RequestResult{}, errors.Join(
			approval.ErrInvalidRequestResult, principalErr, sessionErr,
		)
	}
	return approval.NewRequestResult(approval.RequestResultParams{
		RequestID: requestID, Binding: binding,
		ProposerPrincipalID: principalID, ProposerSessionID: sessionID,
		RequestVersion: 1, CreatedAt: record.createdAt, ExpiresAt: record.expiresAt,
	})
}

func (record policyApprovalRequestRecord) resolution(
	scope network.Scope,
	requestID approval.RequestID,
	idempotencyRecordID publicid.ID,
	decisionHash approval.DecisionHash,
) (approval.Resolution, error) {
	binding, err := record.binding.binding(scope)
	if err != nil {
		return approval.Resolution{}, err
	}
	state, stateErr := approval.ParseState(record.state)
	principalID, principalErr := identity.ParsePrincipalID(record.proposerPrincipal)
	sessionID, sessionErr := accountsession.ParseID(record.proposerSession)
	if stateErr != nil || principalErr != nil || sessionErr != nil {
		return approval.Resolution{}, errors.Join(
			approval.ErrInvalidApprovalResolution,
			stateErr,
			principalErr,
			sessionErr,
		)
	}
	return approval.NewResolution(approval.ResolutionParams{
		Scope: scope, RequestID: requestID, RequestVersion: record.version,
		State: state, Binding: binding, ProposerPrincipalID: principalID,
		ProposerSessionID: sessionID, RequestExpiresAt: record.expiresAt,
		IdempotencyRecordID: idempotencyRecordID, DecisionHash: decisionHash,
	})
}

type policyApprovalEvidenceRecord struct {
	requestID         string
	proposerPrincipal string
	proposerSession   string
	approverPrincipal string
	approverSession   string
	binding           policyApprovalBindingRecord
	requestVersion    int64
	evidenceVersion   int64
	approvedAt        time.Time
	expiresAt         time.Time
}

func scanPolicyApprovalEvidence(row policyApprovalRow) (policyApprovalEvidenceRecord, error) {
	var record policyApprovalEvidenceRecord
	destinations := []any{
		&record.requestID,
		&record.proposerPrincipal,
		&record.proposerSession,
		&record.approverPrincipal,
		&record.approverSession,
	}
	destinations = append(destinations, record.binding.scanDestinations()...)
	destinations = append(
		destinations,
		&record.requestVersion,
		&record.evidenceVersion,
		&record.approvedAt,
		&record.expiresAt,
	)
	if err := row.Scan(destinations...); err != nil {
		return policyApprovalEvidenceRecord{}, err
	}
	return record, nil
}

func (record policyApprovalEvidenceRecord) result(
	scope network.Scope,
	evidenceID approval.EvidenceID,
) (approval.Result, error) {
	requestID, requestErr := approval.ParseRequestID(record.requestID)
	proposerPrincipal, proposerErr := identity.ParsePrincipalID(record.proposerPrincipal)
	proposerSession, proposerSessionErr := accountsession.ParseID(record.proposerSession)
	approverPrincipal, approverErr := identity.ParsePrincipalID(record.approverPrincipal)
	approverSession, approverSessionErr := accountsession.ParseID(record.approverSession)
	binding, bindingErr := record.binding.binding(scope)
	if requestErr != nil || proposerErr != nil || proposerSessionErr != nil ||
		approverErr != nil || approverSessionErr != nil || bindingErr != nil {
		return approval.Result{}, errors.Join(
			approval.ErrInvalidApprovalResult, requestErr, proposerErr,
			proposerSessionErr, approverErr, approverSessionErr, bindingErr,
		)
	}
	return approval.NewResult(approval.ResultParams{
		EvidenceID: evidenceID, RequestID: requestID, Binding: binding,
		ProposerPrincipalID: proposerPrincipal, ProposerSessionID: proposerSession,
		ApproverPrincipalID: approverPrincipal, ApproverSessionID: approverSession,
		RequestVersion: record.requestVersion, EvidenceVersion: record.evidenceVersion,
		ApprovedAt: record.approvedAt, ExpiresAt: record.expiresAt,
	})
}
