package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

// ContractServiceNameManager reads a running share's service names for
// either side, lets the provider replace its suggestions and the consumer
// make one a DNS name of its Network (DNS design D3 §19).
type ContractServiceNameManager interface {
	ContractServiceNames(context.Context, accountsession.Session, network.Scope, sharing.ContractID) (
		sharing.ContractServiceNames, error)
	ReplaceContractServiceNames(context.Context, accountsession.Session, network.Scope, sharing.ContractID, int64,
		[]sharing.ServiceName, publicid.ID) (sharing.ContractServiceNames, bool, error)
	UseContractServiceName(context.Context, accountsession.Session, network.Scope, sharing.ContractID,
		sharing.ServiceName, publicid.ID) (dnszone.Name, dnszone.Zone, error)
}

// contractServiceNameData is one suggestion; for the consumer, the DNS name
// of its Network with that name when one points at the share.
type contractServiceNameData struct {
	Name      string `json:"name"`
	Public    bool   `json:"public"`
	DNSNameID string `json:"dns_name_id,omitempty"`
	DNSZoneID string `json:"dns_zone_id,omitempty"`
}

type contractDNSNameData struct {
	DNSNameID string `json:"dns_name_id"`
	DNSZoneID string `json:"dns_zone_id"`
	Name      string `json:"name"`
}

type contractServiceNamesData struct {
	TrustContractID string                    `json:"trust_contract_id"`
	Side            string                    `json:"side"`
	Version         int64                     `json:"version"`
	Running         bool                      `json:"running"`
	ServiceNames    []contractServiceNameData `json:"service_names"`
	// DNSNames are the consumer's names that point at the share; never
	// sent to the provider.
	DNSNames *[]contractDNSNameData `json:"dns_names,omitempty"`
}

type contractServiceNamesEnvelope struct {
	Data          contractServiceNamesData `json:"data"`
	CorrelationID string                   `json:"correlation_id"`
}

type replaceContractServiceNamesRequest struct {
	ServiceNames []string `json:"service_names"`
}

type useContractServiceNameRequest struct {
	Name string `json:"name"`
}

type contractServiceNameUseData struct {
	DNSNameID string `json:"dns_name_id"`
	DNSZoneID string `json:"dns_zone_id"`
	Name      string `json:"name"`
	Zone      string `json:"zone"`
	Version   int64  `json:"version"`
}

type contractServiceNameUseEnvelope struct {
	Data          contractServiceNameUseData `json:"data"`
	CorrelationID string                     `json:"correlation_id"`
}

func (handler *ManagementHandler) contractServiceNamesData(names sharing.ContractServiceNames,
	now func() bool,
) contractServiceNamesData {
	data := contractServiceNamesData{
		TrustContractID: names.ContractID.String(), Side: "consumer", Version: names.Version, Running: now(),
		ServiceNames: make([]contractServiceNameData, 0, len(names.Names)),
	}
	if names.Provider {
		data.Side = "provider"
	}
	for _, suggested := range handler.serviceNameData(names.Names) {
		item := contractServiceNameData{Name: suggested.Name, Public: suggested.Public}
		for _, made := range names.DNSNames {
			if made.FQDN == suggested.Name {
				item.DNSNameID, item.DNSZoneID = made.ID.String(), made.ZoneID.String()
			}
		}
		data.ServiceNames = append(data.ServiceNames, item)
	}
	if !names.Provider {
		made := make([]contractDNSNameData, 0, len(names.DNSNames))
		for _, name := range names.DNSNames {
			made = append(made, contractDNSNameData{DNSNameID: name.ID.String(), DNSZoneID: name.ZoneID.String(),
				Name: name.FQDN})
		}
		data.DNSNames = &made
	}
	return data
}

// contractServiceNamesPath reads the scope and contract of a service names
// route; false answers the request invalid.
func contractServiceNamesPath(path resourceSharingPath) (network.Scope, sharing.ContractID, bool) {
	scope, err := path.scope()
	if err != nil {
		return network.Scope{}, sharing.ContractID{}, false
	}
	contractID, err := sharing.ParseContractID(path.publicID)
	if err != nil {
		return network.Scope{}, sharing.ContractID{}, false
	}
	return scope, contractID, true
}

func (handler *ManagementHandler) writeContractServiceNames(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, names sharing.ContractServiceNames,
) {
	response.Header().Set("ETag", strongVersionETag(names.Version))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, contractServiceNamesEnvelope{
		Data:          handler.contractServiceNamesData(names, func() bool { return names.Running(time.Now()) }),
		CorrelationID: correlationID.String(),
	})
}

func (handler *ManagementHandler) getContractServiceNames(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path resourceSharingPath, session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || request.Body != nil && request.Body != http.NoBody ||
		len(request.Header.Values("If-Match")) != 0 || len(request.Header.Values("Idempotency-Key")) != 0 ||
		len(request.Header.Values("Content-Type")) != 0 {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	if handler.contractServiceNames == nil {
		writeManagementError(ctx, handler.logger, response, correlationID, sharingUnavailableError())
		return "operation_unavailable"
	}
	scope, contractID, valid := contractServiceNamesPath(path)
	if !valid {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	names, err := handler.contractServiceNames.ContractServiceNames(ctx, session, scope, contractID)
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	if names.ContractID != contractID {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	handler.writeContractServiceNames(ctx, response, correlationID, names)
	return "success"
}

// parseServiceNamesIfMatch reads the version a replace expects: the strong
// ETag of a read, "0" while the suggestions are still the offer's.
func parseServiceNamesIfMatch(values []string) (int64, *managementError) {
	if len(values) == 1 && values[0] == `"0"` {
		return 0, nil
	}
	return parseIfMatch(values)
}

func (handler *ManagementHandler) replaceContractServiceNames(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path resourceSharingPath, session accountsession.Session,
	browser *browserManagementAdmission,
) string {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) ||
		len(request.Header.Values("Idempotency-Key")) != 0 {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	expectedVersion, requestErr := parseServiceNamesIfMatch(request.Header.Values("If-Match"))
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	if handler.contractServiceNames == nil {
		writeManagementError(ctx, handler.logger, response, correlationID, sharingUnavailableError())
		return "operation_unavailable"
	}
	var body replaceContractServiceNamesRequest
	if requestErr = decodeSharingBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	if body.ServiceNames == nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	scope, contractID, valid := contractServiceNamesPath(path)
	if !valid {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	names, nameErr := handler.parseOfferServiceNames(body.ServiceNames)
	if nameErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *nameErr)
		return nameErr.Code
	}
	if resultCode := handler.validateBrowserResourceMutation(ctx, response, correlationID, browser); resultCode != "" {
		return resultCode
	}
	replaced, _, err := handler.contractServiceNames.ReplaceContractServiceNames(ctx, session, scope, contractID,
		expectedVersion, names, correlationID)
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	if replaced.ContractID != contractID || !replaced.Provider {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	handler.writeContractServiceNames(ctx, response, correlationID, replaced)
	return "success"
}

func (handler *ManagementHandler) useContractServiceName(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path resourceSharingPath, session accountsession.Session,
	browser *browserManagementAdmission,
) string {
	if request.URL.RawQuery != "" || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) ||
		len(request.Header.Values("If-Match")) != 0 || len(request.Header.Values("Idempotency-Key")) != 0 {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	if handler.contractServiceNames == nil {
		writeManagementError(ctx, handler.logger, response, correlationID, sharingUnavailableError())
		return "operation_unavailable"
	}
	var body useContractServiceNameRequest
	if requestErr := decodeSharingBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	scope, contractID, valid := contractServiceNamesPath(path)
	name, err := sharing.ParseServiceName(body.Name)
	if !valid || err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	if resultCode := handler.validateBrowserResourceMutation(ctx, response, correlationID, browser); resultCode != "" {
		return resultCode
	}
	made, zone, err := handler.contractServiceNames.UseContractServiceName(ctx, session, scope, contractID, name,
		correlationID)
	if err != nil {
		classified := classifyContractServiceNameError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if made.FQDN != name.String() || made.ZoneID != zone.ID {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, contractServiceNameUseEnvelope{
		Data: contractServiceNameUseData{DNSNameID: made.ID.String(), DNSZoneID: zone.ID.String(), Name: made.FQDN,
			Zone: zone.Domain.String(), Version: made.Version},
		CorrelationID: correlationID.String(),
	})
	return "success"
}

// classifyContractServiceNameError answers a use with the sharing reason,
// or else the DNS one (a name taken, the session may not manage DNS...).
func classifyContractServiceNameError(err error) managementError {
	for _, sharingErr := range []error{sharing.ErrInvalidManagementRequest, sharing.ErrForbidden, sharing.ErrNotFound,
		sharing.ErrServiceNameNotSuggested, sharing.ErrContractEnded, sharing.ErrUnavailable} {
		if errors.Is(err, sharingErr) {
			return classifySharingError(err)
		}
	}
	return classifyDNSNameError(err)
}
