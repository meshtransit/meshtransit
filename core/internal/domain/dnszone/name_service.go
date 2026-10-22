package dnszone

import (
	"context"
	"errors"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// validNamePrefix reports what a name search may start with: lowercase
// letters, digits, hyphens and dots, at most a name long.
func validNamePrefix(prefix string) bool {
	if prefix == "" || len(prefix) > maximumDomainBytes {
		return false
	}
	for i := range len(prefix) {
		character := prefix[i]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '.' {
			return false
		}
	}
	return true
}

// ListNames returns one page of a zone's active names in name order after
// the given one (the zero ID starts at the first); a prefix keeps the names
// that start with it.
func (service *Service) ListNames(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, after NameID, prefix string, limit int) (NameListing, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return NameListing{}, err
	}
	prefix = strings.ToLower(prefix)
	if !zone.IsValid() || limit < 1 || limit > MaximumPage || (after != NameID{} && !after.IsValid()) ||
		(prefix != "" && !validNamePrefix(prefix)) {
		return NameListing{}, ErrInvalid
	}
	return service.store.ListNames(ctx, session, scope, zone, after, prefix, limit)
}

// ReadName returns one active name of a zone.
func (service *Service) ReadName(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, name NameID) (NameReading, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return NameReading{}, err
	}
	if !zone.IsValid() || !name.IsValid() {
		return NameReading{}, ErrInvalid
	}
	return service.store.ReadName(ctx, session, scope, zone, name)
}

// ApplyNames creates, changes and deletes names of one zone in one
// transaction: 1 to MaximumNameOperations operations, each on its own
// name. The checks see the zone as the request leaves it, so a name can be
// deleted and created again as another kind. A failing operation comes back
// as an OperationError naming its position.
func (service *Service) ApplyNames(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, operations []NameOperation, correlationID publicid.ID) (NameResult, error) {
	if err := service.admitWrite(ctx, session, scope, correlationID); err != nil {
		return NameResult{}, err
	}
	if !zone.IsValid() || len(operations) == 0 || len(operations) > MaximumNameOperations {
		return NameResult{}, ErrInvalid
	}
	stored, err := service.store.Read(ctx, session, scope, zone)
	if err != nil {
		return NameResult{}, err
	}
	if stored.Zone.Domain.IsRoot() {
		return NameResult{}, ErrInvalid
	}
	canonical := make([]NameOperation, 0, len(operations))
	for index, operation := range operations {
		checked, err := service.checkNameOperation(operation, stored.Zone.Domain)
		if err == nil && slices.ContainsFunc(canonical, func(other NameOperation) bool {
			return other.NameID == checked.NameID
		}) {
			err = ErrInvalid
		}
		if err != nil {
			return NameResult{}, &OperationError{Index: index, Err: err}
		}
		canonical = append(canonical, checked)
	}
	return service.store.ChangeNames(ctx, NameChange{
		Session: session, Scope: scope, ZoneID: zone, ZoneClass: stored.Zone.Class, Operations: canonical,
		Limits: service.limits, CorrelationID: correlationID,
	})
}

// checkNameOperation validates one operation and returns it canonical: a
// create gets its name's new ID, its label and CNAME in A-labels.
func (service *Service) checkNameOperation(operation NameOperation, domain Domain) (NameOperation, error) {
	switch operation.Operation {
	case OperationCreate:
		if operation.NameID != (NameID{}) || operation.ExpectedVersion != 0 {
			return NameOperation{}, ErrInvalid
		}
		label, err := ParseLabel(operation.Definition.Label)
		if err != nil {
			return NameOperation{}, err
		}
		fqdn, err := NameIn(label, domain)
		if err != nil {
			return NameOperation{}, err
		}
		definition, err := service.canonicalName(operation.Definition, fqdn)
		if err != nil {
			return NameOperation{}, err
		}
		if label == Apex && definition.Kind == NameCNAME {
			return NameOperation{}, ErrCNAMEAtApex
		}
		definition.Label = label
		id, err := service.ids.New()
		if err != nil {
			return NameOperation{}, ErrUnavailable
		}
		return NameOperation{Operation: OperationCreate, NameID: NameID(id), Definition: definition}, nil
	case OperationUpdate:
		if !operation.NameID.IsValid() || operation.ExpectedVersion <= 0 || operation.Definition.Label != "" {
			return NameOperation{}, ErrInvalid
		}
		definition, err := service.canonicalName(operation.Definition, "")
		if err != nil {
			return NameOperation{}, err
		}
		operation.Definition = definition
		return operation, nil
	case OperationDelete:
		if !operation.NameID.IsValid() || operation.ExpectedVersion <= 0 ||
			operation.Definition.Label != "" || operation.Definition.Kind != "" {
			return NameOperation{}, ErrInvalid
		}
		operation.Definition = NameDefinition{}
		return operation, nil
	default:
		return NameOperation{}, ErrInvalid
	}
}

// canonicalName validates a definition's kind and target with its CNAME in
// A-labels; a CNAME never points at its own name (fqdn, when known).
func (service *Service) canonicalName(definition NameDefinition, fqdn string) (NameDefinition, error) {
	canonical := NameDefinition{Kind: definition.Kind, Target: NameTarget{
		DeviceID: definition.Target.DeviceID, Addresses: slices.Clone(definition.Target.Addresses),
	}}
	if definition.Kind == NameCNAME {
		target, err := ParseCNAME(definition.Target.CNAME, service.options.Names)
		if err != nil {
			return NameDefinition{}, err
		}
		if target == fqdn {
			return NameDefinition{}, ErrCNAMELoop
		}
		canonical.Target.CNAME = target
	} else {
		canonical.Target.CNAME = definition.Target.CNAME
	}
	if err := canonical.Validate(); err != nil {
		return NameDefinition{}, err
	}
	return canonical, nil
}

// singleOutcome returns the one outcome of a one-operation change, its
// error without the position.
func singleOutcome(result NameResult, err error) (NameOutcome, error) {
	if failure := (*OperationError)(nil); errors.As(err, &failure) {
		return NameOutcome{}, failure.Err
	}
	if err != nil {
		return NameOutcome{}, err
	}
	if len(result.Outcomes) != 1 {
		return NameOutcome{}, ErrInvalid
	}
	return result.Outcomes[0], nil
}

// CreateName adds one name to a zone.
func (service *Service) CreateName(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, definition NameDefinition, correlationID publicid.ID) (NameOutcome, error) {
	return singleOutcome(service.ApplyNames(ctx, session, scope, zone, []NameOperation{{
		Operation: OperationCreate, Definition: definition,
	}}, correlationID))
}

// UpdateName replaces one name's kind and target at the expected version.
func (service *Service) UpdateName(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, name NameID, expectedVersion int64, definition NameDefinition,
	correlationID publicid.ID) (NameOutcome, error) {
	return singleOutcome(service.ApplyNames(ctx, session, scope, zone, []NameOperation{{
		Operation: OperationUpdate, NameID: name, ExpectedVersion: expectedVersion, Definition: definition,
	}}, correlationID))
}

// DeleteName removes one name at the expected version.
func (service *Service) DeleteName(ctx context.Context, session accountsession.Session, scope network.Scope,
	zone ID, name NameID, expectedVersion int64, correlationID publicid.ID) (NameOutcome, error) {
	return singleOutcome(service.ApplyNames(ctx, session, scope, zone, []NameOperation{{
		Operation: OperationDelete, NameID: name, ExpectedVersion: expectedVersion,
	}}, correlationID))
}
