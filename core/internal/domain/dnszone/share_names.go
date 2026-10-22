package dnszone

import (
	"strings"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

// Service names (DNS design D3): a provider suggests names such as
// app.corp.com on a share offer, and a consumer that approves one gets a
// name of its Network that answers the share's alias. The name lies in the
// longest zone of the Network that covers it or, when none does, in a zone
// of its own: kind host, so every other name of the domain stays with each
// Device's own DNS. These plans check the names as DNS and build the
// changes; the caller applies them in the transaction that accepts the
// offer.

// ServiceName checks a suggested service name as DNS: what a zone's domain
// may be (no special-use name, no public suffix, nothing overlapping the
// mesh names or covering a name MeshTransit must reach), of two labels at
// least. It returns the name canonical, and whether it is on the Internet.
func (service *Service) ServiceName(input string) (string, bool, error) {
	if service == nil {
		return "", false, ErrInvalid
	}
	if !service.options.Enabled {
		return "", false, ErrDisabled
	}
	domain, class, err := ParseDomain(input, service.options.Names)
	if err != nil {
		return "", false, err
	}
	if domain.IsRoot() || !strings.Contains(domain.String(), ".") {
		return "", false, ErrInvalid
	}
	return domain.String(), class == ClassPublic, nil
}

// PlanServiceNameZone returns the change that creates the zone a service
// name gets when no zone of the Network covers it: its own domain, kind
// host, sent to every Device, confirmed when on the Internet (approving the
// name is that confirmation).
func (service *Service) PlanServiceNameZone(session accountsession.Session, scope network.Scope, name string,
	correlationID publicid.ID,
) (Change, error) {
	if service == nil || !session.IsValid() || !scope.IsValid() || !correlationID.IsValid() {
		return Change{}, ErrInvalid
	}
	if !service.options.Enabled {
		return Change{}, ErrDisabled
	}
	domain, class, err := ParseDomain(name, service.options.Names)
	if err != nil {
		return Change{}, err
	}
	if domain.String() != name || domain.IsRoot() {
		return Change{}, ErrInvalid
	}
	definition := Definition{Domain: domain.String(), OtherNames: OtherHost, PublicConfirmed: class == ClassPublic}
	if err := service.check(domain, class, definition); err != nil {
		return Change{}, err
	}
	id, err := service.ids.New()
	if err != nil {
		return Change{}, ErrUnavailable
	}
	return Change{
		Session: session, Scope: scope, Operation: OperationCreate, ZoneID: ID(id), Domain: domain,
		Class: class, ListVersion: PublicListVersion(), Definition: definition.Canonical(),
		Limits: service.limits, CorrelationID: correlationID,
	}, nil
}

// PlanServiceName returns the operation that creates the name in the zone
// of domain zone, pointing at share.
func (service *Service) PlanServiceName(zone Domain, name string, share sharing.ImportedResourceID) (NameOperation,
	error,
) {
	if service == nil || !share.IsValid() || zone.IsRoot() {
		return NameOperation{}, ErrInvalid
	}
	if !service.options.Enabled {
		return NameOperation{}, ErrDisabled
	}
	label := Apex
	if name != zone.String() {
		relative, found := strings.CutSuffix(name, "."+zone.String())
		if !found || relative == "" {
			return NameOperation{}, ErrInvalid
		}
		label = relative
	}
	return service.checkNameOperation(NameOperation{Operation: OperationCreate, Definition: NameDefinition{
		Label: label, Kind: NameAddress, Target: NameTarget{ShareID: share},
	}}, zone)
}

// Limits returns the limits name and zone changes are checked against.
func (service *Service) Limits() Limits { return service.limits }
