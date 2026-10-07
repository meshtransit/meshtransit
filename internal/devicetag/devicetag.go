// Package devicetag holds the Workspace device tag catalog (G2) and the tags
// applied to Devices inside their Network. Access Rules select tags as a
// source or destination. A tagged Device is a service Device: it matches
// rules by tag only and no longer through its owner's Identity Groups.
//
// Each tag names its owners, Identity Groups or built-in roles; the
// Workspace owner owns every tag. A tag owner may tag a Device it owns or a
// Device of a Network where it holds device.manage; device_tag.manage
// applies any tag. PostgreSQL enforces all of this and records evidence.
package devicetag

import (
	"errors"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identitygroup"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

var (
	// ErrInvalid reports a malformed tag, change or result.
	ErrInvalid = errors.New("device tag: invalid request or result")
	// ErrForbidden conceals missing authority or an unavailable scope.
	ErrForbidden = errors.New("device tag: permission denied")
	// ErrNotFound reports an unknown or deleted tag or Device.
	ErrNotFound = errors.New("device tag: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("device tag: version conflict")
	// ErrTagLimit reports a Workspace that already has the maximum tags.
	ErrTagLimit = errors.New("device tag: tag limit reached")
	// ErrUnknownOwner reports an owner group outside the Workspace.
	ErrUnknownOwner = errors.New("device tag: owner is not in this Workspace")
	// ErrNameTaken reports another active tag with the same name.
	ErrNameTaken = errors.New("device tag: name taken")
	// ErrInUse reports a tag that active rules select.
	ErrInUse = errors.New("device tag: selected by active rules")
	// ErrEdgeBudget reports a change that would give one Device more rule
	// edges than its map can carry.
	ErrEdgeBudget = errors.New("device tag: a Device would exceed its rule edge limit")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("device tag: unavailable")
)

// Bounds shared with PostgreSQL schema 121.
const (
	MaximumNameLength        = 48
	MaximumDescriptionLength = 280
	MaximumTags              = 200
	MaximumOwners            = 32
	MaximumTagsPerChange     = 32
)

var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$`)

// OwnerRoles are the built-in roles that may own a tag.
var OwnerRoles = []string{"admin", "auditor", "billing_admin", "it_admin", "network_admin", "security_admin"}

// ID identifies one tag.
type ID publicid.ID

// ParseID validates a canonical tag UUIDv7.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalid
	}
	return ID(id), nil
}

// String returns the canonical public identity.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the identity is a UUIDv7.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }

// ValidName reports a lower-case name of letters, digits and inner hyphens.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// Definition is the editable part of a tag. Owners are sets; Canonical
// orders them so equal definitions compare equal.
type Definition struct {
	Name        string
	Description string
	OwnerGroups []identitygroup.ID
	OwnerRoles  []string
}

// Canonical returns a copy with owners sorted.
func (definition Definition) Canonical() Definition {
	result := Definition{
		Name: definition.Name, Description: definition.Description,
		OwnerGroups: slices.Clone(definition.OwnerGroups), OwnerRoles: slices.Clone(definition.OwnerRoles),
	}
	slices.SortFunc(result.OwnerGroups, func(left, right identitygroup.ID) int {
		switch {
		case left.String() < right.String():
			return -1
		case left.String() > right.String():
			return 1
		default:
			return 0
		}
	})
	slices.Sort(result.OwnerRoles)
	if result.OwnerGroups == nil {
		result.OwnerGroups = []identitygroup.ID{}
	}
	if result.OwnerRoles == nil {
		result.OwnerRoles = []string{}
	}
	return result
}

// IsValid reports a valid name, a bounded plain description and distinct,
// bounded owners.
func (definition Definition) IsValid() bool {
	if !ValidName(definition.Name) ||
		utf8.RuneCountInString(definition.Description) > MaximumDescriptionLength ||
		!identitygroup.PlainText(definition.Description) ||
		len(definition.OwnerGroups)+len(definition.OwnerRoles) > MaximumOwners {
		return false
	}
	groups := make(map[identitygroup.ID]struct{}, len(definition.OwnerGroups))
	for _, group := range definition.OwnerGroups {
		if _, duplicate := groups[group]; duplicate || !group.IsValid() {
			return false
		}
		groups[group] = struct{}{}
	}
	roles := make(map[string]struct{}, len(definition.OwnerRoles))
	for _, role := range definition.OwnerRoles {
		if _, duplicate := roles[role]; duplicate || !slices.Contains(OwnerRoles, role) {
			return false
		}
		roles[role] = struct{}{}
	}
	return true
}

// Tag is one active tag as stored.
type Tag struct {
	ID          ID
	Version     int64
	DeviceCount int
	// RuleCount is how many rules of active releases select the tag.
	RuleCount int
	CreatedAt time.Time
	UpdatedAt time.Time
	Definition
}

// IsValid reports a complete stored tag.
func (tag Tag) IsValid() bool {
	return tag.ID.IsValid() && tag.Version > 0 && tag.DeviceCount >= 0 && tag.RuleCount >= 0 &&
		!tag.CreatedAt.IsZero() && !tag.UpdatedAt.Before(tag.CreatedAt) && tag.Definition.IsValid()
}

// Listing is the Workspace's tag catalog and whether the reader may manage it.
type Listing struct {
	Tags      []Tag
	CanManage bool
}

// Result is a tag after a catalog change. Deleting a tag removes its
// assignments, so Networks that had tagged Devices are rebuilt.
type Result struct {
	Tag      Tag
	Previous *Tag
	Deleted  bool
	Networks []identitygroup.AdvancedNetwork
}

// DeviceTags lists the tags of one Device.
type DeviceTags struct {
	DeviceID node.ID
	Tags     []ID
}

// Apply is where a person may apply one tag in one Network.
type Apply string

// Apply scopes, matching the rule a tag change enforces.
const (
	// ApplyAnyDevice: device_tag.manage, or ownership with device.manage.
	ApplyAnyDevice Apply = "any_device"
	// ApplyOwnDevices: ownership only, on Devices the person owns.
	ApplyOwnDevices Apply = "own_devices"
	// ApplyNone: the tag is on a Device here, but the person may not change it.
	ApplyNone Apply = "none"
)

// MaximumOwnedDevices bounds the owned Devices a tag options read returns.
const MaximumOwnedDevices = 1000

// TagOption is one tag a person may apply in a Network, or that a Device of
// the Network carries.
type TagOption struct {
	ID          ID
	Name        string
	Description string
	Apply       Apply
}

// NetworkOptions are the tags a person may apply in one Network, the tags
// its Devices carry, and the Devices of the Network the person owns.
type NetworkOptions struct {
	Tags         []TagOption
	OwnedDevices []node.ID
}

// AssignmentResult is a Device's tags after a change.
type AssignmentResult struct {
	DeviceID        node.ID
	DeviceName      string
	Tags            []ID
	Added           int
	Removed         int
	NetworkRevision int64
}

// Changed reports whether the Device's tag set changed.
func (result AssignmentResult) Changed() bool { return result.Added+result.Removed > 0 }

// Operation is what a catalog change does.
type Operation string

// Catalog operations.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// Change is one validated catalog change; OwnerRowIDs identify the owner
// rows a create or update writes, one per owner.
type Change struct {
	Session         accountsession.Session
	WorkspaceID     workspace.ID
	Operation       Operation
	TagID           ID
	ExpectedVersion int64
	Definition      Definition
	OwnerRowIDs     []publicid.ID
	CorrelationID   publicid.ID
	EvaluatedAt     time.Time
}

// AssignmentChange adds and removes tags of one Device; each added tag
// carries the identity its assignment row gets.
type AssignmentChange struct {
	Session          accountsession.Session
	Scope            network.Scope
	DeviceID         node.ID
	Add              []ID
	AddAssignmentIDs []publicid.ID
	Remove           []ID
	CorrelationID    publicid.ID
	EvaluatedAt      time.Time
}
