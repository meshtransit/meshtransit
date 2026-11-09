package networksummary

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalidRead rejects a malformed read or result.
	ErrInvalidRead = errors.New("network summary read: invalid request or result")
	// ErrReadForbidden is a Session that may not read the Network or Workspace.
	ErrReadForbidden = errors.New("network summary read: permission denied")
	// ErrReadUnavailable is a store failure.
	ErrReadUnavailable = errors.New("network summary read: unavailable")
	// ErrInvalidResult is an answer from the store that cannot be true: a
	// server fault, never the caller's.
	ErrInvalidResult = errors.New("network summary read: invalid result")
)

const (
	// MaximumPageSize bounds one page of Network summaries.
	MaximumPageSize = 50
	// MaximumQueryLength bounds a search.
	MaximumQueryLength = 128
	// MaximumLinks bounds the Workspace links one overview returns.
	MaximumLinks = 200
)

// Figures is one Network as the Console lists it. Every figure is present
// only when the Session holds its permission and a summary exists.
type Figures struct {
	NetworkID          network.ID
	DisplayName        string
	DisplayCode        string
	Permissions        []string
	ComputedAt         *time.Time
	IPv4Prefix         *netip.Prefix
	AddressesCapacity  *int64
	AddressesInUse     *int64
	AddressesHeld      *int64
	KubernetesClusters *int64
	ActiveDevices      *int64
	RuleCount          *int64
	PolicyRevision     *int64
	PolicyPublishedAt  *time.Time
	PendingApprovals   *int64
	SharesOutActive    *int64
	SharesInActive     *int64
	OffersWaiting      *int64
	Sites              *int64
}

// Page is a page of Networks in Network ID order.
type Page struct {
	Items []Figures
	// Next resumes after the last Network looked at; zero when done.
	Next network.ID
	// SearchedAll is false when a search stopped before the end.
	SearchedAll bool
}

// Side is one end of a Workspace link: one of this Workspace's Networks,
// or another Workspace by its display code.
type Side struct {
	NetworkID   network.ID
	DisplayCode string
}

// Link is the shares from one side to another.
type Link struct {
	From, To        Side
	Active, Waiting int64
}

// Overview is the Workspace at a glance over the Networks a Session may read.
type Overview struct {
	Networks, AddressesTaken                       int64
	ActiveContracts, CrossWorkspace, OffersWaiting int64
	AddressesPartial, SharesPartial, LinksPartial  bool
	OldestComputedAt                               *time.Time
	Links                                          []Link
	WorkspaceDisplayCode                           string
}

// PageRequest is one page read.
type PageRequest struct {
	After network.ID // zero: from the start
	Limit int
	Query string // empty: every Network
}

// Reader reads summaries under fresh Session authority.
type Reader interface {
	ReadPage(context.Context, accountsession.Session, workspace.ID, PageRequest) (Page, error)
	ReadOverview(context.Context, accountsession.Session, workspace.ID) (Overview, error)
	ReadNetwork(context.Context, accountsession.Session, network.Scope) (Figures, error)
}

// ValidPageRequest bounds a page read. The search is counted in characters,
// as the database counts names, and holds no control character.
func ValidPageRequest(request PageRequest) bool {
	if !utf8.ValidString(request.Query) || utf8.RuneCountInString(request.Query) > MaximumQueryLength ||
		strings.ContainsFunc(request.Query, unicode.IsControl) {
		return false
	}
	return request.Limit >= 1 && request.Limit <= MaximumPageSize &&
		(request.After == network.ID{} || request.After.IsValid())
}
