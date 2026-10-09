// Package catalog owns authorized, exact-scope Resource read contracts.
package catalog

import (
	"errors"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
)

const (
	// MaximumPageSize bounds one public Resource catalog page.
	MaximumPageSize = 100
	// MaximumPolicyResources bounds one policy compilation resolution batch.
	MaximumPolicyResources = 256
	// MaximumPolicyResourceGroups bounds one policy compilation group batch.
	MaximumPolicyResourceGroups = 256
)

var (
	// ErrInvalidRequest reports malformed scope, identity, filter, or pagination input.
	ErrInvalidRequest = errors.New("resource catalog: invalid request")
	// ErrInvalidResult reports malformed durable Resource authority evidence.
	ErrInvalidResult = errors.New("resource catalog: invalid result")
	// ErrForbidden hides which live authorization prerequisite failed.
	ErrForbidden = errors.New("resource catalog: forbidden")
	// ErrNotFound hides absent and cross-scope opaque identities alike.
	ErrNotFound = errors.New("resource catalog: not found")
	// ErrConflict reports a collection revision change during pagination.
	ErrConflict = errors.New("resource catalog: collection revision changed")
	// ErrUnavailable reports an unavailable authoritative dependency or transaction.
	ErrUnavailable = errors.New("resource catalog: unavailable")
)

// ResourceParams contains one Device Resource read snapshot.
type ResourceParams struct {
	ID                       resource.ID
	Scope                    network.Scope
	DisplayName              resource.DisplayName
	OwnerPrincipalID         identity.PrincipalID
	CustodianPrincipalID     identity.PrincipalID
	DeviceID                 node.ID
	State                    resource.State
	Provenance               resource.Provenance
	Version                  int64
	TargetGeneration         int64
	SemanticHash             resource.SemanticHash
	ActivatedNetworkRevision int64
	InventoryRevision        int64
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

// Resource is one immutable read snapshot of Device-backed Resource authority.
type Resource struct{ params ResourceParams }

// NewResource validates durable Resource read evidence.
func NewResource(params ResourceParams) (Resource, error) {
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: params.Scope, DisplayName: params.DisplayName,
		OwnerPrincipalID: params.OwnerPrincipalID, CustodianPrincipalID: params.CustodianPrincipalID,
		DeviceID: params.DeviceID, TargetGeneration: params.TargetGeneration,
	})
	valid := err == nil && params.ID.IsValid() && validState(params.State) &&
		params.Provenance == resource.ProvenanceManual && params.Version > 0 &&
		params.TargetGeneration > 0 && params.ActivatedNetworkRevision > 1 &&
		params.InventoryRevision > 1 && params.ActivatedNetworkRevision >= params.InventoryRevision &&
		!params.CreatedAt.IsZero() && !params.UpdatedAt.Before(params.CreatedAt) &&
		params.SemanticHash.IsValid() && revision.SemanticHash() == params.SemanticHash
	if !valid {
		return Resource{}, ErrInvalidResult
	}
	params.CreatedAt = params.CreatedAt.UTC()
	params.UpdatedAt = params.UpdatedAt.UTC()
	return Resource{params: params}, nil
}

// ID returns the stable Resource identity.
func (value Resource) ID() resource.ID { return value.params.ID }

// Scope returns the exact home Network scope.
func (value Resource) Scope() network.Scope { return value.params.Scope }

// DisplayName returns presentation text.
func (value Resource) DisplayName() resource.DisplayName { return value.params.DisplayName }

// OwnerPrincipalID returns the accountability owner.
func (value Resource) OwnerPrincipalID() identity.PrincipalID { return value.params.OwnerPrincipalID }

// CustodianPrincipalID returns the operational custodian.
func (value Resource) CustodianPrincipalID() identity.PrincipalID {
	return value.params.CustodianPrincipalID
}

// DeviceID returns the typed Device target.
func (value Resource) DeviceID() node.ID { return value.params.DeviceID }

// State returns the lifecycle state.
func (value Resource) State() resource.State { return value.params.State }

// Provenance returns how authority entered the control plane.
func (value Resource) Provenance() resource.Provenance { return value.params.Provenance }

// Version returns the Resource authority version.
func (value Resource) Version() int64 { return value.params.Version }

// TargetGeneration returns the active target binding generation.
func (value Resource) TargetGeneration() int64 { return value.params.TargetGeneration }

// SemanticHash returns canonical Resource semantics.
func (value Resource) SemanticHash() resource.SemanticHash { return value.params.SemanticHash }

// ActivatedNetworkRevision returns the activation Network revision.
func (value Resource) ActivatedNetworkRevision() int64 { return value.params.ActivatedNetworkRevision }

// InventoryRevision returns the Resource inventory revision.
func (value Resource) InventoryRevision() int64 { return value.params.InventoryRevision }

// CreatedAt returns the durable creation time.
func (value Resource) CreatedAt() time.Time { return value.params.CreatedAt }

// UpdatedAt returns the durable last-update time.
func (value Resource) UpdatedAt() time.Time { return value.params.UpdatedAt }

// IsValid reports whether all Resource evidence is coherent.
func (value Resource) IsValid() bool {
	validated, err := NewResource(value.params)
	return err == nil && validated.params == value.params
}

// GroupParams contains one active Resource Group read snapshot.
type GroupParams struct {
	ID                       resource.GroupID
	Scope                    network.Scope
	DisplayName              resource.DisplayName
	OwnerPrincipalID         identity.PrincipalID
	CustodianPrincipalID     identity.PrincipalID
	State                    resource.State
	Version                  int64
	DefinitionVersion        int64
	SemanticHash             resource.SemanticHash
	ActivatedNetworkRevision int64
	GroupRevision            int64
	Members                  []resource.Reference
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

// Group is one immutable read snapshot of active Resource Group authority.
type Group struct{ params GroupParams }

// NewGroup validates durable Resource Group read evidence.
func NewGroup(params GroupParams) (Group, error) {
	definition, err := resource.NewGroupDefinition(resource.GroupDefinitionParams{
		Scope: params.Scope, DisplayName: params.DisplayName,
		OwnerPrincipalID: params.OwnerPrincipalID, CustodianPrincipalID: params.CustodianPrincipalID,
		Members: params.Members,
	})
	valid := err == nil && params.ID.IsValid() && validState(params.State) &&
		params.Version > 0 && params.DefinitionVersion > 0 &&
		params.ActivatedNetworkRevision > 1 && params.GroupRevision > 1 &&
		params.ActivatedNetworkRevision >= params.GroupRevision && !params.CreatedAt.IsZero() &&
		!params.UpdatedAt.Before(params.CreatedAt) && params.SemanticHash.IsValid() &&
		definition.SemanticHash() == params.SemanticHash
	if !valid {
		return Group{}, ErrInvalidResult
	}
	params.Members = slices.Clone(params.Members)
	params.CreatedAt = params.CreatedAt.UTC()
	params.UpdatedAt = params.UpdatedAt.UTC()
	return Group{params: params}, nil
}

// ID returns the stable Resource Group identity.
func (value Group) ID() resource.GroupID { return value.params.ID }

// Scope returns the exact home Network scope.
func (value Group) Scope() network.Scope { return value.params.Scope }

// DisplayName returns presentation text.
func (value Group) DisplayName() resource.DisplayName { return value.params.DisplayName }

// OwnerPrincipalID returns the accountability owner.
func (value Group) OwnerPrincipalID() identity.PrincipalID { return value.params.OwnerPrincipalID }

// CustodianPrincipalID returns the operational custodian.
func (value Group) CustodianPrincipalID() identity.PrincipalID {
	return value.params.CustodianPrincipalID
}

// State returns the lifecycle state.
func (value Group) State() resource.State { return value.params.State }

// Version returns the Resource Group authority version.
func (value Group) Version() int64 { return value.params.Version }

// DefinitionVersion returns the active immutable definition version.
func (value Group) DefinitionVersion() int64 { return value.params.DefinitionVersion }

// SemanticHash returns canonical group semantics.
func (value Group) SemanticHash() resource.SemanticHash { return value.params.SemanticHash }

// ActivatedNetworkRevision returns the activation Network revision.
func (value Group) ActivatedNetworkRevision() int64 { return value.params.ActivatedNetworkRevision }

// GroupRevision returns the Resource Group collection revision.
func (value Group) GroupRevision() int64 { return value.params.GroupRevision }

// Members returns a caller-owned immutable membership snapshot.
func (value Group) Members() []resource.Reference { return slices.Clone(value.params.Members) }

// CreatedAt returns the durable creation time.
func (value Group) CreatedAt() time.Time { return value.params.CreatedAt }

// UpdatedAt returns the durable last-update time.
func (value Group) UpdatedAt() time.Time { return value.params.UpdatedAt }

// IsValid reports whether all Resource Group evidence is coherent.
func (value Group) IsValid() bool {
	validated, err := NewGroup(value.params)
	return err == nil && validated.ID() == value.ID() && validated.SemanticHash() == value.SemanticHash()
}

// PageCursor pins continuation to one collection revision and last UUIDv7 identity.
type PageCursor struct {
	revision int64
	after    publicid.ID
}

// NewPageCursor validates a revision-pinned UUIDv7 continuation point.
func NewPageCursor(revision int64, after publicid.ID) (PageCursor, error) {
	cursor := PageCursor{revision: revision, after: after}
	if revision <= 0 || !after.IsValid() {
		return PageCursor{}, ErrInvalidRequest
	}
	return cursor, nil
}

// Revision returns the pinned collection revision.
func (cursor PageCursor) Revision() int64 { return cursor.revision }

// After returns the last public identity in the previous page.
func (cursor PageCursor) After() publicid.ID { return cursor.after }

// IsValid reports whether both continuation fields are present.
func (cursor PageCursor) IsValid() bool { return cursor.revision > 0 && cursor.after.IsValid() }

// ResourcePage is one deterministic Resource list response.
type ResourcePage struct {
	Items    []Resource
	Revision int64
	Next     PageCursor
}

// GroupPage is one deterministic Resource Group list response.
type GroupPage struct {
	Items    []Group
	Revision int64
	Next     PageCursor
}

func validState(state resource.State) bool {
	return state == resource.StateActive || state == resource.StateSuspended || state == resource.StateDeleted
}

// ParseState validates a public lifecycle filter.
func ParseState(value string) (resource.State, error) {
	switch value {
	case "":
		return resource.StateUnknown, nil
	case "active":
		return resource.StateActive, nil
	case "suspended":
		return resource.StateSuspended, nil
	case "deleted":
		return resource.StateDeleted, nil
	default:
		return resource.StateUnknown, ErrInvalidRequest
	}
}

// StateString returns the public lifecycle representation or empty for unknown.
func StateString(state resource.State) string {
	switch state {
	case resource.StateActive:
		return "active"
	case resource.StateSuspended:
		return "suspended"
	case resource.StateDeleted:
		return "deleted"
	default:
		return ""
	}
}
