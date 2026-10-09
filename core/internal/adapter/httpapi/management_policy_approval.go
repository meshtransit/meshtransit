package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	approval "meshtransit.net/core/internal/domain/policy/approval"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/idempotency"
)

const defaultPolicyApprovalPageSize = 50

type policyApprovalPathKind uint8

const (
	policyApprovalPathUnknown policyApprovalPathKind = iota
	policyApprovalPathCollection
	policyApprovalPathItem
	policyApprovalPathApprove
)

type policyApprovalPath struct {
	kind        policyApprovalPathKind
	workspaceID string
	networkID   string
	requestID   string
}

func parsePolicyApprovalPath(request *http.Request) (policyApprovalPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return policyApprovalPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if (len(segments) != 8 && len(segments) != 9 && len(segments) != 11) ||
		segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "policy" ||
		segments[7] != "approval-requests" {
		return policyApprovalPath{}, false
	}
	path := policyApprovalPath{
		kind: policyApprovalPathCollection, workspaceID: segments[3], networkID: segments[5],
	}
	if len(segments) == 9 {
		if segments[8] == "" {
			return policyApprovalPath{}, false
		}
		path.kind = policyApprovalPathItem
		path.requestID = segments[8]
		return path, true
	}
	if len(segments) == 11 {
		if segments[8] == "" || segments[9] != "actions" || segments[10] != "approve" {
			return policyApprovalPath{}, false
		}
		path.kind = policyApprovalPathApprove
		path.requestID = segments[8]
		return path, true
	}
	if strings.HasSuffix(request.URL.Path, "/") {
		return policyApprovalPath{}, false
	}
	return path, true
}

func (path policyApprovalPath) isCollection() bool {
	return path.kind == policyApprovalPathCollection
}

func (path policyApprovalPath) isAction() bool { return path.kind == policyApprovalPathApprove }

func (path policyApprovalPath) allowedMethod(method string) string {
	switch path.kind {
	case policyApprovalPathCollection:
		if method == http.MethodGet || method == http.MethodPost {
			return method
		}
	case policyApprovalPathItem:
		if method == http.MethodGet {
			return method
		}
	case policyApprovalPathApprove:
		if method == http.MethodPost {
			return method
		}
	}
	return ""
}

func (path policyApprovalPath) operation(method string) string {
	switch path.kind {
	case policyApprovalPathCollection:
		if method == http.MethodPost {
			return policyApprovalRequestOperation
		}
		if method == http.MethodGet {
			return policyApprovalListOperation
		}
	case policyApprovalPathItem:
		if method == http.MethodGet {
			return policyApprovalGetOperation
		}
	case policyApprovalPathApprove:
		if method == http.MethodPost {
			return policyApprovalApproveOperation
		}
	}
	return unknownManagementOperation
}

func (path policyApprovalPath) scope() (network.Scope, error) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return network.Scope{}, err
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return network.Scope{}, err
	}
	return network.NewScope(workspaceID, networkID)
}

func (handler *ManagementHandler) handlePolicyApproval(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path policyApprovalPath,
	session accountsession.Session,
	browser *browserManagementAdmission,
) string {
	if (path.kind == policyApprovalPathCollection && request.Method == http.MethodPost) ||
		path.kind == policyApprovalPathApprove {
		if handler.policyApprovals == nil {
			return handler.writePolicyApprovalUnavailable(ctx, response, correlationID)
		}
		if path.kind == policyApprovalPathCollection {
			return handler.requestPolicyApproval(
				ctx, response, request, correlationID, path, session, browser,
			)
		}
		return handler.approvePolicy(
			ctx, response, request, correlationID, path, session, browser,
		)
	}
	if handler.policyApprovalCatalog == nil {
		return handler.writePolicyApprovalUnavailable(ctx, response, correlationID)
	}
	if path.kind == policyApprovalPathCollection {
		return handler.listPolicyApprovals(ctx, response, request, correlationID, path, session)
	}
	return handler.getPolicyApproval(ctx, response, request, correlationID, path, session)
}

type requestPolicyApprovalBody struct {
	Rules                 []publishPolicyRuleRequest `json:"rules"`
	CandidateSemanticHash string                     `json:"candidate_semantic_hash"`
	ImpactHash            string                     `json:"impact_hash"`
	Reason                string                     `json:"reason"`
}

type approvePolicyBody struct {
	CandidateSemanticHash string `json:"candidate_semantic_hash"`
	ImpactHash            string `json:"impact_hash"`
	Reason                string `json:"reason"`
}

func (handler *ManagementHandler) requestPolicyApproval(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path policyApprovalPath,
	session accountsession.Session,
	browser *browserManagementAdmission,
) string {
	intent, decodeErr := handler.decodePolicyApprovalRequest(response, request, path, session)
	if decodeErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *decodeErr)
		return decodeErr.Code
	}
	if err := browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	result, err := handler.policyApprovals.Request(ctx, intent)
	if err != nil {
		classified := classifyPolicyApprovalError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !policyApprovalRequestResultMatches(result, intent) {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	response.Header().Set("ETag", strongVersionETag(result.RequestVersion()))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Location", request.URL.Path+"/"+result.RequestID().String())
	writeManagementJSON(ctx, handler.logger, response, http.StatusCreated, policyApprovalRequestEnvelope{
		Data: policyApprovalRequestedData(result), CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) decodePolicyApprovalRequest(
	response http.ResponseWriter,
	request *http.Request,
	path policyApprovalPath,
	session accountsession.Session,
) (approval.RequestIntent, *managementError) {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return approval.RequestIntent{}, invalidManagementRequest()
	}
	scope, err := path.scope()
	if err != nil {
		return approval.RequestIntent{}, invalidManagementRequest()
	}
	baseRevision, requestErr := parsePolicyIfMatch(request.Header.Values("If-Match"))
	if requestErr != nil {
		return approval.RequestIntent{}, requestErr
	}
	proof, requestErr := handler.policyApprovalIdempotency(request)
	if requestErr != nil {
		return approval.RequestIntent{}, requestErr
	}
	var body requestPolicyApprovalBody
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumPolicyPublicationBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil ||
		body.Rules == nil || len(body.Rules) > policy.MaximumRules {
		return approval.RequestIntent{}, invalidManagementRequest()
	}
	rules := make([]compilation.RuleIntent, len(body.Rules))
	for index, input := range body.Rules {
		rule, err := decodePolicyRuleIntent(scope, input)
		if err != nil {
			return approval.RequestIntent{}, invalidManagementRequest()
		}
		rules[index] = rule
	}
	compilationRequest, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: baseRevision + 1, Rules: rules,
	})
	if err != nil {
		return approval.RequestIntent{}, invalidManagementRequest()
	}
	candidate, impact, reason, err := parsePolicyApprovalEvidence(
		body.CandidateSemanticHash, body.ImpactHash, body.Reason,
	)
	if err != nil {
		return approval.RequestIntent{}, invalidManagementRequest()
	}
	intent, err := approval.NewRequestIntent(approval.RequestIntentParams{
		CompilationRequest: compilationRequest, CandidateSemanticHash: candidate,
		ImpactHash: impact, AccountSession: session, AuditReason: reason,
		IdempotencyEvidence: proof,
	})
	if err != nil {
		return approval.RequestIntent{}, invalidManagementRequest()
	}
	return intent, nil
}

func (handler *ManagementHandler) approvePolicy(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path policyApprovalPath,
	session accountsession.Session,
	browser *browserManagementAdmission,
) string {
	command, decodeErr := handler.decodePolicyApprovalDecision(response, request, path, session)
	if decodeErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *decodeErr)
		return decodeErr.Code
	}
	if err := browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	result, err := handler.policyApprovals.Approve(ctx, command)
	if err != nil {
		classified := classifyPolicyApprovalError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !policyApprovalDecisionResultMatches(result, command) {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	response.Header().Set("ETag", strongVersionETag(result.RequestVersion()))
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, policyApprovalDecisionEnvelope{
		Data: policyApprovalApprovedData(result), CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) decodePolicyApprovalDecision(
	response http.ResponseWriter,
	request *http.Request,
	path policyApprovalPath,
	session accountsession.Session,
) (approval.Command, *managementError) {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return approval.Command{}, invalidManagementRequest()
	}
	scope, err := path.scope()
	if err != nil {
		return approval.Command{}, invalidManagementRequest()
	}
	requestID, err := approval.ParseRequestID(path.requestID)
	if err != nil {
		return approval.Command{}, invalidManagementRequest()
	}
	expectedVersion, requestErr := parseIfMatch(request.Header.Values("If-Match"))
	if requestErr != nil {
		return approval.Command{}, requestErr
	}
	proof, requestErr := handler.policyApprovalIdempotency(request)
	if requestErr != nil {
		return approval.Command{}, requestErr
	}
	var body approvePolicyBody
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumManagementBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil {
		return approval.Command{}, invalidManagementRequest()
	}
	candidate, impact, reason, err := parsePolicyApprovalEvidence(
		body.CandidateSemanticHash, body.ImpactHash, body.Reason,
	)
	if err != nil {
		return approval.Command{}, invalidManagementRequest()
	}
	command, err := approval.NewCommand(approval.CommandParams{
		Scope: scope, RequestID: requestID, ExpectedRequestVersion: expectedVersion,
		CandidateSemanticHash: candidate, ImpactHash: impact, AccountSession: session,
		AuditReason: reason, IdempotencyEvidence: proof,
	})
	if err != nil {
		return approval.Command{}, invalidManagementRequest()
	}
	return command, nil
}

func (handler *ManagementHandler) policyApprovalIdempotency(
	request *http.Request,
) (idempotency.Proof, *managementError) {
	rawKey := singleHeader(request.Header, "Idempotency-Key")
	if rawKey == "" {
		return idempotency.Proof{}, invalidManagementRequest()
	}
	proof, err := handler.idempotency.Proof(rawKey)
	if err != nil || !proof.IsValid() {
		return idempotency.Proof{}, invalidManagementRequest()
	}
	return proof, nil
}

func parsePolicyApprovalEvidence(
	candidateValue string,
	impactValue string,
	reasonValue string,
) (publication.SemanticHash, simulation.ImpactHash, approval.AuditReason, error) {
	candidateDigest, err := parsePolicyApprovalDigest(candidateValue)
	if err != nil {
		return publication.SemanticHash{}, simulation.ImpactHash{}, approval.AuditReason{}, err
	}
	impactDigest, err := parsePolicyApprovalDigest(impactValue)
	if err != nil {
		return publication.SemanticHash{}, simulation.ImpactHash{}, approval.AuditReason{}, err
	}
	candidate, err := publication.NewSemanticHash(candidateDigest)
	if err != nil {
		return publication.SemanticHash{}, simulation.ImpactHash{}, approval.AuditReason{}, err
	}
	impact, err := simulation.NewImpactHash(impactDigest)
	if err != nil {
		return publication.SemanticHash{}, simulation.ImpactHash{}, approval.AuditReason{}, err
	}
	reason, err := approval.NewAuditReason(reasonValue)
	return candidate, impact, reason, err
}

func parsePolicyApprovalDigest(value string) ([sha256.Size]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return [sha256.Size]byte{}, approval.ErrInvalidBinding
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	if digest == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, approval.ErrInvalidBinding
	}
	return digest, nil
}

func (handler *ManagementHandler) getPolicyApproval(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path policyApprovalPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || !validResourceReadHeaders(request) {
		return handler.writePolicyApprovalRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writePolicyApprovalRequestError(ctx, response, correlationID)
	}
	requestID, err := approval.ParseRequestID(path.requestID)
	if err != nil {
		return handler.writePolicyApprovalRequestError(ctx, response, correlationID)
	}
	value, err := handler.policyApprovalCatalog.Get(ctx, session, scope, requestID)
	if err != nil {
		classified := classifyPolicyApprovalCatalogError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	response.Header().Set("ETag", strongVersionETag(value.RequestVersion()))
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, policyApprovalCatalogEnvelope{
		Data: policyApprovalCatalogDataFromSnapshot(value), CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) listPolicyApprovals(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path policyApprovalPath,
	session accountsession.Session,
) string {
	if !validResourceReadHeaders(request) {
		return handler.writePolicyApprovalRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writePolicyApprovalRequestError(ctx, response, correlationID)
	}
	state, limit, after, requestErr := parsePolicyApprovalListQuery(request.URL.RawQuery)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	page, err := handler.policyApprovalCatalog.List(ctx, session, scope, state, limit, after)
	if err != nil {
		classified := classifyPolicyApprovalCatalogError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	items := make([]policyApprovalCatalogData, len(page.Items))
	for index, item := range page.Items {
		items[index] = policyApprovalCatalogDataFromSnapshot(item)
	}
	next, err := encodePolicyApprovalPageToken(state, page.Next)
	if err != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, policyApprovalListEnvelope{
		Data: items, NextPageToken: next, CorrelationID: correlationID.String(),
	})
	return "success"
}

type policyApprovalPageToken struct {
	Version int    `json:"v"`
	State   string `json:"state"`
	After   string `json:"after"`
}

func parsePolicyApprovalListQuery(
	rawQuery string,
) (approval.State, int, approval.RequestID, *managementError) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return approval.StateUnknown, 0, approval.RequestID{}, invalidManagementRequest()
	}
	for key, entries := range values {
		if (key != "state" && key != "page_size" && key != "page_token") ||
			len(entries) != 1 || entries[0] == "" {
			return approval.StateUnknown, 0, approval.RequestID{}, invalidManagementRequest()
		}
	}
	state := approval.StateUnknown
	if value := values.Get("state"); value != "" {
		state, err = approval.ParseState(value)
		if err != nil {
			return approval.StateUnknown, 0, approval.RequestID{}, invalidManagementRequest()
		}
	}
	limit := defaultPolicyApprovalPageSize
	if rawLimit := values.Get("page_size"); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > approval.MaximumCatalogPageSize ||
			strconv.Itoa(limit) != rawLimit {
			return approval.StateUnknown, 0, approval.RequestID{}, invalidManagementRequest()
		}
	}
	after := approval.RequestID{}
	if encoded := values.Get("page_token"); encoded != "" {
		after, err = decodePolicyApprovalPageToken(encoded, state)
		if err != nil {
			return approval.StateUnknown, 0, approval.RequestID{}, invalidManagementRequest()
		}
	}
	return state, limit, after, nil
}

func encodePolicyApprovalPageToken(state approval.State, after approval.RequestID) (string, error) {
	if !after.IsValid() {
		return "", nil
	}
	payload, err := json.Marshal(policyApprovalPageToken{
		Version: 1, State: catalogApprovalStateString(state), After: after.String(),
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodePolicyApprovalPageToken(encoded string, state approval.State) (approval.RequestID, error) {
	if len(encoded) > 512 {
		return approval.RequestID{}, approval.ErrInvalidCatalogRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return approval.RequestID{}, approval.ErrInvalidCatalogRequest
	}
	var wire policyApprovalPageToken
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || ensureJSONEnd(decoder) != nil ||
		wire.Version != 1 || wire.State != catalogApprovalStateString(state) {
		return approval.RequestID{}, approval.ErrInvalidCatalogRequest
	}
	return approval.ParseRequestID(wire.After)
}

func catalogApprovalStateString(state approval.State) string {
	if state == approval.StateUnknown {
		return ""
	}
	return state.String()
}

type policyApprovalBindingData struct {
	BaselineRevisionVector simulatedPolicyRevisionVector `json:"baseline_revision_vector"`
	ProposedRevisionVector simulatedPolicyRevisionVector `json:"proposed_revision_vector"`
	CandidateSemanticHash  string                        `json:"candidate_semantic_hash"`
	CompilerFormatVersion  int                           `json:"compiler_format_version"`
	ImpactHash             string                        `json:"impact_hash"`
}

type policyApprovalRequested struct {
	RequestID           string                    `json:"request_id"`
	State               string                    `json:"state"`
	RequestVersion      int64                     `json:"request_version"`
	ProposerPrincipalID string                    `json:"proposer_principal_id"`
	Binding             policyApprovalBindingData `json:"binding"`
	CreatedAt           time.Time                 `json:"created_at"`
	ExpiresAt           time.Time                 `json:"expires_at"`
}

type policyApprovalApproved struct {
	RequestID           string                    `json:"request_id"`
	State               string                    `json:"state"`
	RequestVersion      int64                     `json:"request_version"`
	EvidenceID          string                    `json:"evidence_id"`
	EvidenceVersion     int64                     `json:"evidence_version"`
	ProposerPrincipalID string                    `json:"proposer_principal_id"`
	ApproverPrincipalID string                    `json:"approver_principal_id"`
	Binding             policyApprovalBindingData `json:"binding"`
	ApprovedAt          time.Time                 `json:"approved_at"`
	ExpiresAt           time.Time                 `json:"expires_at"`
}

type policyApprovalDecisionData struct {
	EvidenceID          string    `json:"evidence_id"`
	EvidenceVersion     int64     `json:"evidence_version"`
	ApproverPrincipalID string    `json:"approver_principal_id"`
	Reason              string    `json:"reason"`
	ApprovedAt          time.Time `json:"approved_at"`
}

type policyApprovalConsumptionData struct {
	PolicyReleaseID string    `json:"policy_release_id"`
	PolicyRevision  int64     `json:"policy_revision"`
	ConsumedAt      time.Time `json:"consumed_at"`
}

type policyApprovalCatalogData struct {
	RequestID           string                         `json:"request_id"`
	State               string                         `json:"state"`
	RequestVersion      int64                          `json:"request_version"`
	ProposerPrincipalID string                         `json:"proposer_principal_id"`
	ProposalReason      string                         `json:"proposal_reason"`
	Binding             policyApprovalBindingData      `json:"binding"`
	CreatedAt           time.Time                      `json:"created_at"`
	ExpiresAt           time.Time                      `json:"expires_at"`
	UpdatedAt           time.Time                      `json:"updated_at"`
	Decision            *policyApprovalDecisionData    `json:"decision,omitempty"`
	Consumption         *policyApprovalConsumptionData `json:"consumption,omitempty"`
}

type policyApprovalRequestEnvelope struct {
	Data          policyApprovalRequested `json:"data"`
	CorrelationID string                  `json:"correlation_id"`
}

type policyApprovalDecisionEnvelope struct {
	Data          policyApprovalApproved `json:"data"`
	CorrelationID string                 `json:"correlation_id"`
}

type policyApprovalCatalogEnvelope struct {
	Data          policyApprovalCatalogData `json:"data"`
	CorrelationID string                    `json:"correlation_id"`
}

type policyApprovalListEnvelope struct {
	Data          []policyApprovalCatalogData `json:"data"`
	NextPageToken string                      `json:"next_page_token,omitempty"`
	CorrelationID string                      `json:"correlation_id"`
}

func policyApprovalBindingDataFromBinding(binding approval.Binding) policyApprovalBindingData {
	candidate := binding.CandidateSemanticHash().Bytes()
	impact := binding.ImpactHash().Bytes()
	return policyApprovalBindingData{
		BaselineRevisionVector: encodePolicySimulationVector(binding.BaselineVector()),
		ProposedRevisionVector: encodePolicySimulationVector(binding.ProposedVector()),
		CandidateSemanticHash:  hex.EncodeToString(candidate[:]),
		CompilerFormatVersion:  binding.CompilerFormatVersion(),
		ImpactHash:             hex.EncodeToString(impact[:]),
	}
}

func policyApprovalRequestedData(result approval.RequestResult) policyApprovalRequested {
	return policyApprovalRequested{
		RequestID: result.RequestID().String(), State: result.State().String(),
		RequestVersion:      result.RequestVersion(),
		ProposerPrincipalID: result.ProposerPrincipalID().String(),
		Binding:             policyApprovalBindingDataFromBinding(result.Binding()),
		CreatedAt:           result.CreatedAt(), ExpiresAt: result.ExpiresAt(),
	}
}

func policyApprovalApprovedData(result approval.Result) policyApprovalApproved {
	return policyApprovalApproved{
		RequestID: result.RequestID().String(), State: result.State().String(),
		RequestVersion: result.RequestVersion(), EvidenceID: result.EvidenceID().String(),
		EvidenceVersion:     result.EvidenceVersion(),
		ProposerPrincipalID: result.ProposerPrincipalID().String(),
		ApproverPrincipalID: result.ApproverPrincipalID().String(),
		Binding:             policyApprovalBindingDataFromBinding(result.Binding()),
		ApprovedAt:          result.ApprovedAt(), ExpiresAt: result.ExpiresAt(),
	}
}

func policyApprovalCatalogDataFromSnapshot(value approval.Snapshot) policyApprovalCatalogData {
	data := policyApprovalCatalogData{
		RequestID: value.RequestID().String(), State: value.State().String(),
		RequestVersion:      value.RequestVersion(),
		ProposerPrincipalID: value.ProposerPrincipalID().String(),
		ProposalReason:      value.ProposalReason().String(),
		Binding:             policyApprovalBindingDataFromBinding(value.Binding()),
		CreatedAt:           value.CreatedAt(), ExpiresAt: value.ExpiresAt(), UpdatedAt: value.UpdatedAt(),
	}
	if decision, found := value.Decision(); found {
		data.Decision = &policyApprovalDecisionData{
			EvidenceID: decision.EvidenceID().String(), EvidenceVersion: decision.EvidenceVersion(),
			ApproverPrincipalID: decision.ApproverPrincipalID().String(),
			Reason:              decision.Reason().String(), ApprovedAt: decision.ApprovedAt(),
		}
	}
	if consumption, found := value.Consumption(); found {
		data.Consumption = &policyApprovalConsumptionData{
			PolicyReleaseID: consumption.ReleaseID().String(),
			PolicyRevision:  consumption.PolicyRevision(), ConsumedAt: consumption.ConsumedAt(),
		}
	}
	return data
}

func policyApprovalRequestResultMatches(
	result approval.RequestResult,
	intent approval.RequestIntent,
) bool {
	return result.IsValid() && result.Scope() == intent.CompilationRequest().Scope() &&
		result.Binding().CandidateSemanticHash() == intent.CandidateSemanticHash() &&
		result.Binding().ImpactHash() == intent.ImpactHash() &&
		result.ProposerPrincipalID() == intent.AccountSession().PrincipalID() &&
		result.ProposerSessionID() == intent.AccountSession().ID()
}

func policyApprovalDecisionResultMatches(result approval.Result, command approval.Command) bool {
	return result.IsValid() && result.Scope() == command.Scope() &&
		result.RequestID() == command.RequestID() &&
		result.RequestVersion() == command.ExpectedRequestVersion()+1 &&
		result.Binding().CandidateSemanticHash() == command.CandidateSemanticHash() &&
		result.Binding().ImpactHash() == command.ImpactHash() &&
		result.ApproverPrincipalID() == command.AccountSession().PrincipalID() &&
		result.ApproverSessionID() == command.AccountSession().ID()
}

func classifyPolicyApprovalError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	case errors.Is(err, approval.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden",
			Message: "the request is not authorized",
		}
	case errors.Is(err, approval.ErrCandidateChanged), errors.Is(err, approval.ErrImpactChanged),
		errors.Is(err, approval.ErrRequestVersionConflict),
		errors.Is(err, approval.ErrRequestStateConflict), errors.Is(err, approval.ErrRequestExpired),
		errors.Is(err, approval.ErrIndependentApproverRequired):
		return managementError{
			Status: http.StatusConflict, Code: "approval_conflict",
			Message: "the Policy approval request is unavailable or changed",
		}
	case errors.Is(err, approval.ErrInvalidRequestIntent),
		errors.Is(err, approval.ErrInvalidApprovalCommand),
		errors.Is(err, approval.ErrInvalidBinding):
		return *invalidManagementRequest()
	default:
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
			Message: "the operation is temporarily unavailable", Retryable: true,
		}
	}
}

func classifyPolicyApprovalCatalogError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	case errors.Is(err, approval.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden",
			Message: "the request is not authorized",
		}
	case errors.Is(err, approval.ErrRequestNotFound):
		return managementError{
			Status: http.StatusNotFound, Code: "not_found",
			Message: "the requested resource is unavailable",
		}
	case errors.Is(err, approval.ErrInvalidCatalogRequest):
		return *invalidManagementRequest()
	case errors.Is(err, approval.ErrInvalidCatalogResult):
		return internalManagementError()
	default:
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
			Message: "the operation is temporarily unavailable", Retryable: true,
		}
	}
}

func (handler *ManagementHandler) writePolicyApprovalUnavailable(
	ctx context.Context,
	response http.ResponseWriter,
	correlationID publicid.ID,
) string {
	writeManagementError(ctx, handler.logger, response, correlationID, managementError{
		Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
		Message: "the operation is temporarily unavailable", Retryable: true,
	})
	return "operation_unavailable"
}

func (handler *ManagementHandler) writePolicyApprovalRequestError(
	ctx context.Context,
	response http.ResponseWriter,
	correlationID publicid.ID,
) string {
	requestErr := invalidManagementRequest()
	writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
	return requestErr.Code
}
