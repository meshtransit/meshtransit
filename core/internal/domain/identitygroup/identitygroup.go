// Package identitygroup holds Network Identity Groups (G2n): named sets of
// a Network's members that the Network's Access Rules select as a source. A Device belongs to
// the groups of its owner while it carries no tag; a tagged Device is a
// service Device that matches rules by tag alone. Membership is resolved when
// maps are built, so a change reaches maps without republishing policy.
// PostgreSQL stores groups, checks the permission each change needs and
// records the evidence.
package identitygroup

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalid reports a malformed group, change or result.
	ErrInvalid = errors.New("identity group: invalid request or result")
	// ErrForbidden conceals missing authority or an unavailable Network.
	ErrForbidden = errors.New("identity group: permission denied")
	// ErrNotFound reports an unknown or deleted group.
	ErrNotFound = errors.New("identity group: not found")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("identity group: version conflict")
	// ErrIneligibleMember reports a principal that is not an active member of the Network.
	ErrIneligibleMember = errors.New("identity group: principal is not an active member of this Network")
	// ErrGroupLimit reports a Network that already has the maximum groups.
	ErrGroupLimit = errors.New("identity group: group limit reached")
	// ErrMemberLimit reports a group that would exceed the maximum members.
	ErrMemberLimit = errors.New("identity group: member limit reached")
	// ErrNameTaken reports another active group with the same name.
	ErrNameTaken = errors.New("identity group: name taken")
	// ErrInUse reports a group that active rules select or that owns a tag.
	ErrInUse = errors.New("identity group: selected by active rules or owns tags")
	// ErrEdgeBudget reports a change that would give one Device more rule
	// edges than its map can carry.
	ErrEdgeBudget = errors.New("identity group: a Device would exceed its rule edge limit")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("identity group: unavailable")
)

// Bounds shared with PostgreSQL schema 121.
const (
	MaximumNameLength        = 64
	MaximumDescriptionLength = 280
	MaximumGroups            = 500
	MaximumMembers           = 10000
	MaximumMembersPerChange  = 150
	MaximumMemberPage        = 500
)

// ID identifies one Identity Group.
type ID publicid.ID

// ParseID validates a canonical Identity Group UUIDv7.
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

// PlainText reports valid UTF-8 without control characters.
func PlainText(value string) bool {
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

// Definition is the editable part of a group.
type Definition struct {
	Name        string
	Description string
}

// IsValid reports a trimmed, bounded name and a bounded description, both
// free of control characters.
func (definition Definition) IsValid() bool {
	name := strings.TrimSpace(definition.Name)
	return name == definition.Name && name != "" &&
		utf8.RuneCountInString(name) <= MaximumNameLength && PlainText(name) &&
		utf8.RuneCountInString(definition.Description) <= MaximumDescriptionLength &&
		PlainText(definition.Description)
}

// Group is one active group as stored.
type Group struct {
	ID          ID
	Version     int64
	MemberCount int
	// RuleCount is how many rules of active releases select the group.
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

// Listing is a Network's groups and whether the reader may change them.
type Listing struct {
	Groups    []Group
	CanManage bool
}

// Member is one principal of a group. A member whose membership or
// principal is no longer active stays listed but grants nothing.
type Member struct {
	PrincipalID publicid.ID
	DisplayName string
	Active      bool
	AddedAt     time.Time
}

// MemberPage is one page of a group's members, ordered by principal ID.
type MemberPage struct {
	Group   Group
	Members []Member
	HasMore bool
}

// AdvancedNetwork is a Network whose revision advanced because a change
// altered what its active rules select.
type AdvancedNetwork struct {
	NetworkID       network.ID
	NetworkRevision int64
	GroupRevision   int64
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
	// Networks lists the Networks whose maps the change rebuilt; empty when
	// no active rule selects the group.
	Networks []AdvancedNetwork
}

// AccessAffecting reports whether the change gave or took access.
func (result MembershipResult) AccessAffecting() bool {
	return result.Added+result.Removed > 0 && len(result.Networks) > 0
}

// Operation is what a definition change does.
type Operation string

// Definition operations.
const (
	OperationCreate Operation = "create"
	OperationUpdate Operation = "update"
	OperationDelete Operation = "delete"
)

// Change is one validated definition change.
type Change struct {
	Session         accountsession.Session
	Scope           network.Scope
	Operation       Operation
	GroupID         ID
	ExpectedVersion int64
	Definition      Definition
	CorrelationID   publicid.ID
}

// MembershipChange adds and removes principals; each added principal carries
// the identity its membership row gets.
type MembershipChange struct {
	Session         accountsession.Session
	Scope           network.Scope
	GroupID         ID
	ExpectedVersion int64
	Add             []publicid.ID
	AddMemberIDs    []publicid.ID
	Remove          []publicid.ID
	CorrelationID   publicid.ID
}
