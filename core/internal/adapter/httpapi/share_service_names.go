package httpapi

import (
	"context"
	"net/http"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/sharing"
)

// ServiceNameChecker checks a service name a share offer suggests as DNS
// (DNS design D3): what a zone's domain may be. It returns the name
// canonical, and whether it is on the Internet.
type ServiceNameChecker interface {
	ServiceName(string) (string, bool, error)
}

// OfferServiceNameReader reads the service names an offer suggests, for its
// provider or consumer Network.
type OfferServiceNameReader interface {
	OfferServiceNames(context.Context, network.Scope, sharing.OfferID) ([]sharing.ServiceName, error)
}

// parseOfferServiceNames checks the names an offer suggests: canonical, at
// most eight, none twice, each one a zone's domain may be. A failure names
// the name's place.
func (handler *ManagementHandler) parseOfferServiceNames(values []string) ([]sharing.ServiceName,
	*managementError,
) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > sharing.MaximumServiceNames {
		return nil, &managementError{Status: http.StatusConflict, Code: "dns_service_name_limit",
			Message: "An offer suggests at most 8 service names"}
	}
	if handler.serviceNames == nil {
		classified := classifyDNSZoneError(dnszone.ErrDisabled)
		return nil, &classified
	}
	names := make([]sharing.ServiceName, 0, len(values))
	for index, value := range values {
		failed := func(err error) *managementError {
			classified := classifyDNSZoneError(err)
			at := index
			classified.OperationIndex = &at
			return &classified
		}
		canonical, _, err := handler.serviceNames.ServiceName(value)
		if err != nil {
			return nil, failed(err)
		}
		name, err := sharing.ParseServiceName(canonical)
		if err != nil {
			return nil, failed(dnszone.ErrInvalid)
		}
		for _, earlier := range names {
			if earlier == name {
				return nil, failed(dnszone.ErrInvalid)
			}
		}
		names = append(names, name)
	}
	return names, nil
}

// parseServiceNameDecisions reads the answers of an accept; each name is in
// the canonical form the offer shows.
func parseServiceNameDecisions(values []serviceNameDecisionRequest) ([]sharing.ServiceNameDecision, bool) {
	if len(values) == 0 {
		return nil, true
	}
	if len(values) > sharing.MaximumServiceNames {
		return nil, false
	}
	decisions := make([]sharing.ServiceNameDecision, 0, len(values))
	for _, value := range values {
		name, err := sharing.ParseServiceName(value.Name)
		if err != nil || (value.Decision != "approve" && value.Decision != "decline") {
			return nil, false
		}
		decisions = append(decisions, sharing.ServiceNameDecision{Name: name, Approve: value.Decision == "approve"})
	}
	return decisions, true
}

// serviceNameData shows suggested names with whether each is on the
// Internet; without a checker none is marked.
func (handler *ManagementHandler) serviceNameData(names []sharing.ServiceName) []shareOfferServiceNameData {
	if len(names) == 0 {
		return nil
	}
	data := make([]shareOfferServiceNameData, 0, len(names))
	for _, name := range names {
		item := shareOfferServiceNameData{Name: name.String()}
		if handler.serviceNames != nil {
			if _, public, err := handler.serviceNames.ServiceName(name.String()); err == nil {
				item.Public = public
			}
		}
		data = append(data, item)
	}
	return data
}
