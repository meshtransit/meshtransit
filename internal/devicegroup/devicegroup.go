// Package devicegroup holds Network Device Groups (G1): named sets of
// Devices of one Network that Access Rules select instead of single Devices.
// Membership is resolved when maps are built, so adding a Device to a group
// gives it the group's access without republishing policy. PostgreSQL stores
// groups, checks the permission each change needs and records the evidence.
package devicegroup

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalid reports a malformed group, change or result.
	ErrInvalid = errors.New("device group: invalid request or result")
	// ErrForbidden conceals missing authority or an unavailable Network.
	ErrForbidden = errors.New("device group: permission denied")
	// ErrNotFound reports an unknown or deleted group.
	ErrNotFound = errors.New("device group: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("device group: version conflict")
	// ErrIneligibleDevice reports a Device that is not an active Device of the Network.
	ErrIneligibleDevice = errors.New("device group: Device is not an active Device of this Network")
	// ErrGroupLimit reports a Network that already has the maximum groups.
	ErrGroupLimit = errors.New("device group: group limit reached")
	// ErrMemberLimit reports a group that would exceed the maximum members.
	ErrMemberLimit = errors.New("device group: member limit reached")
	// ErrNameTaken reports another active group with the same name.
	ErrNameTaken = errors.New("device group: name taken")
	// ErrInUse reports a group the active policy release still selects.
	ErrInUse = errors.New("device group: selected by active rules")
	// ErrEdgeBudget reports a change that would give one Device more rule
	// edges than its map can carry.
	ErrEdgeBudget = errors.New("device group: a Device would exceed its rule edge limit")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("device group: unavailable")
)

// Bounds shared with PostgreSQL schema 120.
const (
	MaximumNameLength        = 64
	MaximumDescriptionLength = 280
	MaximumGroups            = 200
	MaximumMembers           = 5000
	MaximumMembersPerChange  = 150
	MaximumMemberPage        = 500
)

// ID identifies one Device Group.
type ID publicid.ID

// ParseID validates a canonical Device Group UUIDv7.
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

// Definition is the editable part of a group.
type Definition struct {
	Name        string
	Description string
}

func plainText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// IsValid reports a trimmed, bounded name and a bounded description, both
// free of control characters.
func (definition Definition) IsValid() bool {
	name := strings.TrimSpace(definition.Name)
	return name == definition.Name && name != "" &&
		utf8.RuneCountInString(name) <= MaximumNameLength && plainText(name) &&
		utf8.RuneCountInString(definition.Description) <= MaximumDescriptionLength &&
		plainText(definition.Description)
}

// Group is one active group as stored.
type Group struct {
	ID          ID
	Version     int64
	MemberCount int
	// RuleCount is how many rules of the active release select the group.
	RuleCount int
	CreatedAt time.Time
	UpdatedAt time.Time
	Definition
}

// IsValid reports a complete stored group.
func (group Group) IsValid() bool {
	return group.ID.IsValid() && group.Version > 0 && group.MemberCount >= 0 &&
		group.MemberCount <= MaximumMembers && group.RuleCount >= 0 &&
		!group.CreatedAt.IsZero() && !group.UpdatedAt.Before(group.CreatedAt) && group.Definition.IsValid()
}

// Listing is a Network's groups and what the reader may change.
type Listing struct {
	Groups           []Group
	CanManage        bool
	CanManageMembers bool
}

// Member is one Device of a group. An inactive Device stays listed but
// grants nothing until it is active again.
type Member struct {
	DeviceID node.ID
	Name     string
	Active   bool
	AddedAt  time.Time
}

// MemberPage is one page of a group's members, ordered by Device ID.
type MemberPage struct {
	Group   Group
	Members []Member
	HasMore bool
}

// Result is a group after a definition change.
type Result struct {
	Group    Group
	Previous *Group
	Deleted  bool
}

// MembershipResult is a group after a membership change.
type MembershipResult struct {
	Group   Group
	Added   int
	Removed int
	// AccessAffecting is true when the set changed and active rules select
	// the group, so Devices gained or lost access.
	AccessAffecting bool
}
