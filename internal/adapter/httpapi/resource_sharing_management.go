package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const defaultSharingPageSize = 50

type resourceSharingKind uint8

const (
	resourceSharingUnknown resourceSharingKind = iota
	resourceSharingOfferCollection
	resourceSharingOfferItem
	resourceSharingOfferAction
	resourceSharingContractAction
)

type resourceSharingPath struct {
	kind        resourceSharingKind
	workspaceID string
	networkID   string
	publicID    string
	action      string
}

func parseResourceSharingPath(request *http.Request) (resourceSharingPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return resourceSharingPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if (len(segments) != 7 && len(segments) != 8 && len(segments) != 10) ||
		segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" {
		return resourceSharingPath{}, false
	}
	path := resourceSharingPath{workspaceID: segments[3], networkID: segments[5]}
	switch segments[6] {
	case "share-offers":
		path.kind = resourceSharingOfferCollection
		if len(segments) >= 8 {
			path.kind = resourceSharingOfferItem
			path.publicID = segments[7]
		}
		if len(segments) == 10 {
			if segments[8] != "actions" ||
				(segments[9] != "accept" && segments[9] != "reject" && segments[9] != "revoke") {
				return resourceSharingPath{}, false
			}
			path.kind = resourceSharingOfferAction
			path.action = segments[9]
		}
	case "trust-contracts":
		if len(segments) != 10 || segments[8] != "actions" ||
			(segments[9] != "activate" && segments[9] != "revoke") {
			return resourceSharingPath{}, false
		}
		path.kind = resourceSharingContractAction
		path.publicID = segments[7]
		path.action = segments[9]
	default:
		return resourceSharingPath{}, false
	}
	return path, true
}

func (path resourceSharingPath) scope() (network.Scope, error) {
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

func (path resourceSharingPath) isCollection() bool {
	return path.kind == resourceSharingOfferCollection
}

func (path resourceSharingPath) isAction() bool {
	return path.kind == resourceSharingOfferAction || path.kind == resourceSharingContractAction
}

func (path resourceSharingPath) allowedMethod(requestMethod string) string {
	if path.isCollection() {
		if requestMethod == http.MethodGet {
			return http.MethodGet
		}
		return http.MethodPost
	}
	if path.isAction() {
		return http.MethodPost
	}
	return http.MethodGet
}

func (path resourceSharingPath) operation(requestMethod string) string {
	switch path.kind {
	case resourceSharingOfferCollection:
		if requestMethod == http.MethodGet {
			return shareOfferListOperation
		}
		return shareOfferCreateOperation
	case resourceSharingOfferItem:
		return shareOfferGetOperation
	case resourceSharingContractAction:
		if path.action == "activate" {
			return shareContractActivateOperation
		}
		return shareContractRevokeOperation
	case resourceSharingOfferAction:
		switch path.action {
		case "accept":
			return shareOfferAcceptOperation
		case "reject":
			return shareOfferRejectOperation
		case "revoke":
			return shareOfferRevokeOperation
		}
	}
	return unknownManagementOperation
}

type sharingPortRangeRequest struct {
	First int `json:"first"`
	Last  int `json:"last"`
}

type sharingTrafficRequest struct {
	Protocol              string                    `json:"protocol"`
	DestinationPortRanges []sharingPortRangeRequest `json:"destination_port_ranges"`
}

type createShareOfferRequest struct {
	ConsumerWorkspaceID string                  `json:"consumer_workspace_id"`
	ConsumerNetworkID   string                  `json:"consumer_network_id"`
	ResourceID          string                  `json:"resource_id"`
	MaximumTraffic      []sharingTrafficRequest `json:"maximum_traffic"`
	ExpiresAt           string                  `json:"expires_at"`
	Reason              string                  `json:"reason"`
}

type decideShareOfferRequest struct {
	ProviderWorkspaceID string `json:"provider_workspace_id"`
	ProviderNetworkID   string `json:"provider_network_id"`
	ConsumerWorkspaceID string `json:"consumer_workspace_id"`
	ConsumerNetworkID   string `json:"consumer_network_id"`
	OfferToken          string `json:"offer_token"`
	ImportedDisplayName string `json:"imported_display_name,omitempty"`
	Reason              string `json:"reason"`
}

type revokeTrustContractRequest struct {
	ProviderWorkspaceID string `json:"provider_workspace_id"`
	ProviderNetworkID   string `json:"provider_network_id"`
	ConsumerWorkspaceID string `json:"consumer_workspace_id"`
	ConsumerNetworkID   string `json:"consumer_network_id"`
	Reason              string `json:"reason"`
}

type sharingPortRangeData struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

type sharingTrafficData struct {
	Protocol              string                 `json:"protocol"`
	DestinationPortRanges []sharingPortRangeData `json:"destination_port_ranges"`
}

type shareOfferData struct {
	OfferID                 string               `json:"offer_id"`
	ExportID                string               `json:"export_id"`
	ScopeRelation           string               `json:"scope_relation"`
	ProviderWorkspaceID     string               `json:"provider_workspace_id"`
	ProviderNetworkID       string               `json:"provider_network_id"`
	ConsumerWorkspaceID     string               `json:"consumer_workspace_id"`
	ConsumerNetworkID       string               `json:"consumer_network_id"`
	ResourceID              string               `json:"resource_id"`
	ResourceVersion         int64                `json:"resource_version"`
	TargetGeneration        int64                `json:"target_generation"`
	MaximumTraffic          []sharingTrafficData `json:"maximum_traffic"`
	State                   string               `json:"state"`
	Version                 int64                `json:"version"`
	AcceptedTrustContractID string               `json:"accepted_trust_contract_id,omitempty"`
	CreatedAt               time.Time            `json:"created_at"`
	ExpiresAt               time.Time            `json:"expires_at"`
	ProviderNetworkRevision int64                `json:"provider_network_revision,omitempty"`
	ProviderSharingRevision int64                `json:"provider_sharing_revision,omitempty"`
	ConsumerNetworkRevision int64                `json:"consumer_network_revision,omitempty"`
	ConsumerSharingRevision int64                `json:"consumer_sharing_revision,omitempty"`
	OfferToken              string               `json:"offer_token,omitempty"`
}

type shareContractData struct {
	TrustContractID         string `json:"trust_contract_id"`
	ImportedResourceID      string `json:"imported_resource_id"`
	OfferID                 string `json:"offer_id"`
	State                   string `json:"state"`
	Version                 int64  `json:"version"`
	ImportedResourceVersion int64  `json:"imported_resource_version"`
}

type shareOfferEnvelope struct {
	Data          shareOfferData `json:"data"`
	CorrelationID string         `json:"correlation_id"`
}

type shareContractEnvelope struct {
	Data          shareContractData `json:"data"`
	CorrelationID string            `json:"correlation_id"`
}

type shareOfferListEnvelope struct {
	Data          []shareOfferData `json:"data"`
	NextPageToken string           `json:"next_page_token,omitempty"`
	Revision      int64            `json:"sharing_revision"`
	CorrelationID string           `json:"correlation_id"`
}

func (handler *ManagementHandler) handleResourceSharing(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceSharingPath,
	session accountsession.Session,
) string {
	if handler.resourceSharing == nil {
		writeManagementError(ctx, handler.logger, response, correlationID, sharingUnavailableError())
		return "operation_unavailable"
	}
	switch path.kind {
	case resourceSharingOfferCollection:
		if request.Method == http.MethodGet {
			return handler.listShareOffers(ctx, response, request, correlationID, path, session)
		}
		return handler.createShareOffer(ctx, response, request, correlationID, path, session)
	case resourceSharingOfferItem:
		return handler.getShareOffer(ctx, response, request, correlationID, path, session)
	case resourceSharingOfferAction:
		return handler.decideShareOffer(ctx, response, request, correlationID, path, session)
	case resourceSharingContractAction:
		return handler.changeTrustContract(ctx, response, request, correlationID, path, session)
	default:
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
}

func (handler *ManagementHandler) createShareOffer(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceSharingPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) ||
		len(request.Header.Values("If-Match")) != 0 {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	proof, requestErr := handler.sharingIdempotencyProof(request)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	var body createShareOfferRequest
	if requestErr = decodeSharingBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	providerScope, err := path.scope()
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	consumerScope, err := parseSharingScope(body.ConsumerWorkspaceID, body.ConsumerNetworkID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	resourceID, err := resource.ParseID(body.ResourceID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	traffic, err := parseSharingTraffic(body.MaximumTraffic)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, body.ExpiresAt)
	if err != nil || expiresAt.Format(time.RFC3339Nano) != body.ExpiresAt {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	reason, err := sharing.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	command, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope, ResourceID: resourceID,
		MaximumTraffic: traffic, ExpiresAt: expiresAt, AccountSession: session,
		Reason: reason, Idempotency: proof,
	})
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	result, err := handler.resourceSharing.CreateOffer(ctx, command)
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	offer, hasOffer := result.Offer()
	token, hasToken := result.Token()
	_, hasContract := result.Contract()
	if !result.IsValid() || !hasOffer || !hasToken || hasContract ||
		offer.Offer().ProviderScope() != providerScope || offer.Offer().ConsumerScope() != consumerScope ||
		offer.Resource().ResourceID() != resourceID ||
		offer.Offer().MaximumTraffic().Hash() != traffic.Hash() {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	data := shareOfferDataFromSnapshot(offer)
	data.ProviderNetworkRevision = result.ProviderNetworkRevision()
	data.ProviderSharingRevision = result.ProviderSharingRevision()
	data.ConsumerNetworkRevision = result.ConsumerNetworkRevision()
	data.ConsumerSharingRevision = result.ConsumerSharingRevision()
	tokenBytes := token.Bytes()
	data.OfferToken = base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	response.Header().Set("ETag", strongVersionETag(offer.Offer().Version()))
	response.Header().Set("Location", request.URL.Path+"/"+offer.Offer().ID().String())
	writeManagementJSON(ctx, handler.logger, response, http.StatusCreated, shareOfferEnvelope{
		Data: data, CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) decideShareOffer(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceSharingPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	expectedVersion, requestErr := parseIfMatch(request.Header.Values("If-Match"))
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	proof, requestErr := handler.sharingIdempotencyProof(request)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	var body decideShareOfferRequest
	if requestErr = decodeSharingBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	localScope, err := path.scope()
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	providerScope, err := parseSharingScope(body.ProviderWorkspaceID, body.ProviderNetworkID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	consumerScope, err := parseSharingScope(body.ConsumerWorkspaceID, body.ConsumerNetworkID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	action := sharing.DecisionActionUnknown
	switch path.action {
	case "accept":
		action = sharing.DecisionActionAccept
	case "reject":
		action = sharing.DecisionActionReject
	case "revoke":
		action = sharing.DecisionActionRevoke
	}
	if action == sharing.DecisionActionRevoke && localScope != providerScope ||
		action != sharing.DecisionActionRevoke && localScope != consumerScope {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	offerID, err := sharing.ParseOfferID(path.publicID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	token, err := parseSharingToken(body.OfferToken)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	var importedName resource.DisplayName
	if body.ImportedDisplayName != "" {
		importedName, err = resource.ParseDisplayName(body.ImportedDisplayName)
		if err != nil {
			return handler.writeSharingRequestError(ctx, response, correlationID)
		}
	}
	reason, err := sharing.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	command, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope, OfferID: offerID,
		ExpectedOfferVersion: expectedVersion, Token: token, Action: action,
		ImportedDisplayName: importedName, AccountSession: session, Reason: reason,
		Idempotency: proof,
	})
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	result, err := handler.resourceSharing.DecideOffer(ctx, command)
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	offer, hasOffer := result.Offer()
	if !result.IsValid() || !hasOffer || offer.Offer().ID() != offerID {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	if action == sharing.DecisionActionAccept {
		contract, found := result.Contract()
		if !found || contract.State() != sharing.ContractStateActivating {
			return handler.writeSharingInternalError(ctx, response, correlationID)
		}
		response.Header().Set("ETag", strongVersionETag(contract.Version()))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, shareContractEnvelope{
			Data:          shareContractDataFromResult(contract, result.ImportedResourceVersion()),
			CorrelationID: correlationID.String(),
		})
		return "success"
	}
	response.Header().Set("ETag", strongVersionETag(offer.Offer().Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, shareOfferEnvelope{
		Data: shareOfferDataFromSnapshot(offer), CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) changeTrustContract(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceSharingPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	expectedVersion, requestErr := parseIfMatch(request.Header.Values("If-Match"))
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	proof, requestErr := handler.sharingIdempotencyProof(request)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	var body revokeTrustContractRequest
	if requestErr = decodeSharingBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	localScope, err := path.scope()
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	providerScope, err := parseSharingScope(body.ProviderWorkspaceID, body.ProviderNetworkID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	consumerScope, err := parseSharingScope(body.ConsumerWorkspaceID, body.ConsumerNetworkID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	contractID, err := sharing.ParseContractID(path.publicID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	reason, err := sharing.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	var result sharing.MutationResult
	if path.action == "activate" {
		if localScope != consumerScope {
			return handler.writeSharingRequestError(ctx, response, correlationID)
		}
		command, commandErr := sharing.NewActivateContract(sharing.ActivateContractParams{
			ProviderScope: providerScope, ConsumerScope: consumerScope, ContractID: contractID,
			ExpectedContractVersion: expectedVersion, AccountSession: session,
			Reason: reason, Idempotency: proof,
		})
		if commandErr != nil {
			return handler.writeSharingRequestError(ctx, response, correlationID)
		}
		result, err = handler.resourceSharing.ActivateContract(ctx, command)
	} else {
		command, commandErr := sharing.NewRevokeContract(sharing.RevokeContractParams{
			ProviderScope: providerScope, ConsumerScope: consumerScope, ContractID: contractID,
			ExpectedContractVersion: expectedVersion, LocalScope: localScope,
			AccountSession: session, Reason: reason, Idempotency: proof,
		})
		if commandErr != nil {
			return handler.writeSharingRequestError(ctx, response, correlationID)
		}
		result, err = handler.resourceSharing.RevokeContract(ctx, command)
	}
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	contract, found := result.Contract()
	if !result.IsValid() || !found || contract.ID() != contractID ||
		(path.action == "activate" && contract.State() != sharing.ContractStateActive) ||
		(path.action == "revoke" && contract.State() != sharing.ContractStateRevoked) {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	response.Header().Set("ETag", strongVersionETag(contract.Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, shareContractEnvelope{
		Data:          shareContractDataFromResult(contract, result.ImportedResourceVersion()),
		CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) getShareOffer(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceSharingPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || request.Body != nil && request.Body != http.NoBody ||
		len(request.Header.Values("If-Match")) != 0 ||
		len(request.Header.Values("Idempotency-Key")) != 0 ||
		len(request.Header.Values("Content-Type")) != 0 {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	offerID, err := sharing.ParseOfferID(path.publicID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	snapshot, err := handler.resourceSharing.GetOffer(ctx, session, scope, offerID)
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	if !snapshot.IsValid() || snapshot.Offer().ID() != offerID ||
		(scope != snapshot.Offer().ProviderScope() && scope != snapshot.Offer().ConsumerScope()) {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	response.Header().Set("ETag", strongVersionETag(snapshot.Offer().Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, shareOfferEnvelope{
		Data: shareOfferDataFromSnapshot(snapshot), CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) listShareOffers(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceSharingPath,
	session accountsession.Session,
) string {
	if request.Body != nil && request.Body != http.NoBody ||
		len(request.Header.Values("If-Match")) != 0 ||
		len(request.Header.Values("Idempotency-Key")) != 0 ||
		len(request.Header.Values("Content-Type")) != 0 {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	direction, state, limit, cursor, requestErr := parseSharingListQuery(request.URL.RawQuery)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	page, err := handler.resourceSharing.ListOffers(
		ctx, session, scope, direction, state, limit, cursor,
	)
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	if !page.IsValid() {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	items := page.Items()
	data := make([]shareOfferData, len(items))
	for index, item := range items {
		if direction == sharing.DirectionOutgoing && item.Offer().ProviderScope() != scope ||
			direction == sharing.DirectionIncoming && item.Offer().ConsumerScope() != scope {
			return handler.writeSharingInternalError(ctx, response, correlationID)
		}
		data[index] = shareOfferDataFromSnapshot(item)
	}
	nextToken := ""
	if next, found := page.Next(); found {
		nextToken, err = encodeSharingPageCursor(direction, state, next)
		if err != nil {
			return handler.writeSharingInternalError(ctx, response, correlationID)
		}
	}
	response.Header().Set("ETag", strongVersionETag(page.Revision()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, shareOfferListEnvelope{
		Data: data, NextPageToken: nextToken, Revision: page.Revision(),
		CorrelationID: correlationID.String(),
	})
	return "success"
}

func parseSharingScope(workspaceValue, networkValue string) (network.Scope, error) {
	workspaceID, err := workspace.ParseID(workspaceValue)
	if err != nil {
		return network.Scope{}, err
	}
	networkID, err := network.ParseID(networkValue)
	if err != nil {
		return network.Scope{}, err
	}
	return network.NewScope(workspaceID, networkID)
}

func parseSharingTraffic(values []sharingTrafficRequest) (sharing.TrafficSet, error) {
	if len(values) == 0 || len(values) > sharing.MaximumTrafficConstraints {
		return sharing.TrafficSet{}, sharing.ErrInvalidTrafficSet
	}
	constraints := make([]sharing.TrafficConstraint, len(values))
	for index, value := range values {
		protocol := parsePolicyProtocol(value.Protocol)
		if !protocol.IsValid() || len(value.DestinationPortRanges) > policy.MaximumPortRangesPerRule {
			return sharing.TrafficSet{}, sharing.ErrInvalidTrafficConstraint
		}
		ranges := make([]policy.PortRange, len(value.DestinationPortRanges))
		for rangeIndex, input := range value.DestinationPortRanges {
			if input.First <= 0 || input.First > math.MaxUint16 ||
				input.Last <= 0 || input.Last > math.MaxUint16 {
				return sharing.TrafficSet{}, sharing.ErrInvalidTrafficConstraint
			}
			portRange, err := policy.NewPortRange(uint16(input.First), uint16(input.Last))
			if err != nil {
				return sharing.TrafficSet{}, err
			}
			ranges[rangeIndex] = portRange
		}
		constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
			Protocol: protocol, DestinationPortRanges: ranges,
		})
		if err != nil {
			return sharing.TrafficSet{}, err
		}
		constraints[index] = constraint
	}
	return sharing.NewTrafficSet(constraints)
}

func parseSharingToken(encoded string) (sharing.OfferToken, error) {
	if len(encoded) > 64 {
		return sharing.OfferToken{}, sharing.ErrInvalidManagementRequest
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return sharing.OfferToken{}, sharing.ErrInvalidManagementRequest
	}
	var fixed [32]byte
	copy(fixed[:], decoded)
	return sharing.NewOfferToken(fixed)
}

func decodeSharingBody(response http.ResponseWriter, request *http.Request, target any) *managementError {
	request.Body = http.MaxBytesReader(response, request.Body, maximumManagementBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || ensureJSONEnd(decoder) != nil {
		return invalidManagementRequest()
	}
	return nil
}

func (handler *ManagementHandler) sharingIdempotencyProof(
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

type sharingPageCursorWire struct {
	Version   int    `json:"v"`
	Direction string `json:"direction"`
	State     string `json:"state"`
	Revision  int64  `json:"revision"`
	After     string `json:"after"`
}

func parseSharingListQuery(
	rawQuery string,
) (sharing.Direction, sharing.OfferState, int, sharing.PageCursor, *managementError) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return 0, 0, 0, sharing.PageCursor{}, invalidManagementRequest()
	}
	for key, entries := range values {
		if (key != "direction" && key != "state" && key != "page_size" && key != "page_token") ||
			len(entries) != 1 || entries[0] == "" {
			return 0, 0, 0, sharing.PageCursor{}, invalidManagementRequest()
		}
	}
	direction := parseSharingDirection(values.Get("direction"))
	state, stateOK := parseSharingOfferState(values.Get("state"), true)
	if !direction.IsValid() || !stateOK {
		return 0, 0, 0, sharing.PageCursor{}, invalidManagementRequest()
	}
	limit := defaultSharingPageSize
	if rawLimit := values.Get("page_size"); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > sharing.MaximumManagementPageSize ||
			strconv.Itoa(limit) != rawLimit {
			return 0, 0, 0, sharing.PageCursor{}, invalidManagementRequest()
		}
	}
	cursor := sharing.EmptyPageCursor()
	if encoded := values.Get("page_token"); encoded != "" {
		cursor, err = decodeSharingPageCursor(encoded, direction, state)
		if err != nil {
			return 0, 0, 0, sharing.PageCursor{}, invalidManagementRequest()
		}
	}
	return direction, state, limit, cursor, nil
}

func parseSharingDirection(value string) sharing.Direction {
	switch value {
	case "outgoing":
		return sharing.DirectionOutgoing
	case "incoming":
		return sharing.DirectionIncoming
	default:
		return sharing.DirectionUnknown
	}
}

func sharingDirectionString(direction sharing.Direction) string {
	if direction == sharing.DirectionOutgoing {
		return "outgoing"
	}
	if direction == sharing.DirectionIncoming {
		return "incoming"
	}
	return ""
}

func parseSharingOfferState(value string, allowAll bool) (sharing.OfferState, bool) {
	switch value {
	case "":
		return sharing.OfferStateUnknown, allowAll
	case "offered":
		return sharing.OfferStateOffered, true
	case "accepted":
		return sharing.OfferStateAccepted, true
	case "rejected":
		return sharing.OfferStateRejected, true
	case "expired":
		return sharing.OfferStateExpired, true
	case "revoked":
		return sharing.OfferStateRevoked, true
	default:
		return sharing.OfferStateUnknown, false
	}
}

func sharingOfferStateString(state sharing.OfferState) string {
	switch state {
	case sharing.OfferStateOffered:
		return "offered"
	case sharing.OfferStateAccepted:
		return "accepted"
	case sharing.OfferStateRejected:
		return "rejected"
	case sharing.OfferStateExpired:
		return "expired"
	case sharing.OfferStateRevoked:
		return "revoked"
	default:
		return ""
	}
}

func sharingContractStateString(state sharing.ContractState) string {
	switch state {
	case sharing.ContractStateActivating:
		return "activating"
	case sharing.ContractStateActive:
		return "active"
	case sharing.ContractStateRevoked:
		return "revoked"
	case sharing.ContractStateExpired:
		return "expired"
	case sharing.ContractStateInvalidated:
		return "invalidated"
	default:
		return ""
	}
}

func encodeSharingPageCursor(
	direction sharing.Direction,
	state sharing.OfferState,
	cursor sharing.PageCursor,
) (string, error) {
	if !direction.IsValid() || !cursor.IsValid() {
		return "", sharing.ErrInvalidManagementRequest
	}
	payload, err := json.Marshal(sharingPageCursorWire{
		Version: 1, Direction: sharingDirectionString(direction),
		State: sharingOfferStateString(state), Revision: cursor.Revision(),
		After: cursor.After().String(),
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeSharingPageCursor(
	encoded string,
	direction sharing.Direction,
	state sharing.OfferState,
) (sharing.PageCursor, error) {
	if len(encoded) > 512 {
		return sharing.PageCursor{}, sharing.ErrInvalidManagementRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return sharing.PageCursor{}, sharing.ErrInvalidManagementRequest
	}
	var wire sharingPageCursorWire
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
		wire.Direction != sharingDirectionString(direction) ||
		wire.State != sharingOfferStateString(state) {
		return sharing.PageCursor{}, sharing.ErrInvalidManagementRequest
	}
	after, err := sharing.ParseOfferID(wire.After)
	if err != nil {
		return sharing.PageCursor{}, sharing.ErrInvalidManagementRequest
	}
	return sharing.NewPageCursor(wire.Revision, after)
}

func shareOfferDataFromSnapshot(snapshot sharing.OfferSnapshot) shareOfferData {
	offer := snapshot.Offer()
	binding := snapshot.Resource()
	data := shareOfferData{
		OfferID: offer.ID().String(), ExportID: offer.ExportID().String(),
		ScopeRelation:       offer.ScopeRelation().String(),
		ProviderWorkspaceID: offer.ProviderScope().WorkspaceID().String(),
		ProviderNetworkID:   offer.ProviderScope().NetworkID().String(),
		ConsumerWorkspaceID: offer.ConsumerScope().WorkspaceID().String(),
		ConsumerNetworkID:   offer.ConsumerScope().NetworkID().String(),
		ResourceID:          binding.ResourceID().String(), ResourceVersion: binding.ResourceVersion(),
		TargetGeneration: binding.TargetGeneration(),
		MaximumTraffic:   sharingTrafficDataFromSet(offer.MaximumTraffic()),
		State:            sharingOfferStateString(offer.State()), Version: offer.Version(),
		CreatedAt: snapshot.CreatedAt(), ExpiresAt: offer.ExpiresAt(),
	}
	if contractID := offer.AcceptedContractID(); contractID.IsValid() {
		data.AcceptedTrustContractID = contractID.String()
	}
	return data
}

func sharingTrafficDataFromSet(set sharing.TrafficSet) []sharingTrafficData {
	constraints := set.Constraints()
	result := make([]sharingTrafficData, len(constraints))
	for index, constraint := range constraints {
		ranges := constraint.DestinationPortRanges()
		encoded := make([]sharingPortRangeData, len(ranges))
		for rangeIndex, value := range ranges {
			encoded[rangeIndex] = sharingPortRangeData{First: value.First(), Last: value.Last()}
		}
		protocol := "icmp"
		if constraint.Protocol() == policy.ProtocolTCP {
			protocol = "tcp"
		} else if constraint.Protocol() == policy.ProtocolUDP {
			protocol = "udp"
		}
		result[index] = sharingTrafficData{Protocol: protocol, DestinationPortRanges: encoded}
	}
	return result
}

func shareContractDataFromResult(contract sharing.Contract, importedVersion int64) shareContractData {
	return shareContractData{
		TrustContractID:    contract.ID().String(),
		ImportedResourceID: contract.ImportedResourceID().String(),
		OfferID:            contract.OfferID().String(), State: sharingContractStateString(contract.State()),
		Version: contract.Version(), ImportedResourceVersion: importedVersion,
	}
}

func (handler *ManagementHandler) writeSharingRequestError(
	ctx context.Context,
	response http.ResponseWriter,
	correlationID publicid.ID,
) string {
	requestErr := invalidManagementRequest()
	writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
	return requestErr.Code
}

func (handler *ManagementHandler) writeSharingError(
	ctx context.Context,
	response http.ResponseWriter,
	correlationID publicid.ID,
	err error,
) string {
	classified := classifySharingError(err)
	writeManagementError(ctx, handler.logger, response, correlationID, classified)
	return classified.Code
}

func (handler *ManagementHandler) writeSharingInternalError(
	ctx context.Context,
	response http.ResponseWriter,
	correlationID publicid.ID,
) string {
	classified := internalManagementError()
	writeManagementError(ctx, handler.logger, response, correlationID, classified)
	return classified.Code
}

func classifySharingError(err error) managementError {
	switch {
	case errors.Is(err, sharing.ErrInvalidManagementRequest):
		return *invalidManagementRequest()
	case errors.Is(err, sharing.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden", Message: "the operation is not permitted",
		}
	case errors.Is(err, sharing.ErrNotFound):
		return managementError{
			Status: http.StatusNotFound, Code: "not_found", Message: "the requested resource is unavailable",
		}
	case errors.Is(err, sharing.ErrConflict):
		return managementError{
			Status: http.StatusConflict, Code: "conflict",
			Message: "sharing authority changed; refresh and retry",
		}
	case errors.Is(err, sharing.ErrUnavailable):
		return sharingUnavailableError()
	default:
		return internalManagementError()
	}
}

func sharingUnavailableError() managementError {
	return managementError{
		Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
		Message: "Resource Sharing is temporarily unavailable", Retryable: true,
	}
}
