// Package sessioncontext owns authenticated Console session projections.
package sessioncontext

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	// MaximumPageSize bounds one management-scope projection page.
	MaximumPageSize         = 100
	maximumDisplayNameBytes = 128
)

var (
	// ErrInvalidRequest reports malformed projection input or dependencies.
	ErrInvalidRequest = errors.New("session context: invalid management scope request")
	// ErrInvalidResult reports malformed or out-of-session durable evidence.
	ErrInvalidResult = errors.New("session context: invalid management scope result")
	// ErrUnauthenticated conceals stale or revoked durable session authority.
	ErrUnauthenticated = errors.New("session context: unauthenticated")
	// ErrUnavailable reports an unavailable durable projection dependency.
	ErrUnavailable = errors.New("session context: management scopes unavailable")
)

// ManagementScope is one Network where the current Principal has projected UI permissions.
// These permissions never substitute for operation-level server authorization.
type ManagementScope struct {
	networkID   network.ID
	displayName string
	permissions []authorization.Permission
}

// NewManagementScope validates one server-owned Network projection.
func NewManagementScope(
	networkID network.ID,
	displayName string,
	permissions []authorization.Permission,
) (ManagementScope, error) {
	value := ManagementScope{
		networkID: networkID, displayName: displayName,
		permissions: append([]authorization.Permission(nil), permissions...),
	}
	if !value.IsValid() {
		return ManagementScope{}, ErrInvalidResult
	}
	return value, nil
}

// NetworkID returns the public Network identity.
func (value ManagementScope) NetworkID() network.ID { return value.networkID }

// DisplayName returns the bounded current Network label.
func (value ManagementScope) DisplayName() string { return value.displayName }

// Permissions returns a defensive copy of the projected UI permission set.
func (value ManagementScope) Permissions() []authorization.Permission {
	return append([]authorization.Permission(nil), value.permissions...)
}

// IsValid reports whether the projection is safe and canonical.
func (value ManagementScope) IsValid() bool {
	if !value.networkID.IsValid() || !validDisplayName(value.displayName) ||
		len(value.permissions) < 1 || len(value.permissions) > 10 {
		return false
	}
	for index, permission := range value.permissions {
		if !isConsoleManagementPermission(permission) ||
			(index > 0 && value.permissions[index-1] >= permission) {
			return false
		}
		definition, ok := authorization.LookupPermission(permission)
		if !ok || definition.Permission() != permission {
			return false
		}
	}
	return true
}

func isConsoleManagementPermission(permission authorization.Permission) bool {
	switch permission {
	case authorization.PermissionDeviceRead,
		authorization.PermissionNetworkRead,
		authorization.PermissionPolicyApprove,
		authorization.PermissionPolicyRead,
		authorization.PermissionPolicyPublish,
		authorization.PermissionPolicyValidate,
		authorization.PermissionShareAccept,
		authorization.PermissionShareOffer,
		authorization.PermissionShareRead,
		authorization.PermissionShareRevoke:
		return true
	default:
		return false
	}
}

// ReadResult is untrusted durable evidence returned to the validating service.
type ReadResult struct {
	WorkspaceID          workspace.ID
	WorkspaceDisplayName string
	Scopes               []ManagementScope
}

// Reader loads one fresh login-Workspace projection from durable authority.
type Reader interface {
	ReadManagementScopes(
		context.Context,
		accountsession.Session,
		network.ID,
		int,
		time.Time,
	) (ReadResult, error)
}

// Page is one validated deterministic UUIDv7-keyset page.
type Page struct {
	workspaceID          workspace.ID
	workspaceDisplayName string
	items                []ManagementScope
	next                 network.ID
}

// WorkspaceID returns the login Workspace public identity.
func (page Page) WorkspaceID() workspace.ID { return page.workspaceID }

// WorkspaceDisplayName returns the bounded current Workspace label.
func (page Page) WorkspaceDisplayName() string { return page.workspaceDisplayName }

// Items returns a defensive copy of the page.
func (page Page) Items() []ManagementScope {
	return append([]ManagementScope(nil), page.items...)
}

// Next returns the next Network cursor when another page exists.
func (page Page) Next() (network.ID, bool) { return page.next, page.next.IsValid() }

// Clock supplies one authority-evaluation instant.
type Clock interface {
	Now() time.Time
}

// Service validates server-authoritative management-scope projections.
type Service struct {
	reader Reader
	clock  Clock
}

// NewService constructs a projection service through explicit dependencies.
func NewService(reader Reader, clock Clock) (*Service, error) {
	if reader == nil || clock == nil {
		return nil, ErrInvalidRequest
	}
	return &Service{reader: reader, clock: clock}, nil
}

// List returns one fresh page for the Session's exact login Workspace.
func (service *Service) List(
	ctx context.Context,
	session accountsession.Session,
	limit int,
	after network.ID,
) (Page, error) {
	if ctx == nil || service == nil || service.reader == nil || service.clock == nil ||
		!session.IsValid() || limit < 1 || limit > MaximumPageSize ||
		(!after.IsValid() && after != (network.ID{})) {
		return Page{}, ErrInvalidRequest
	}
	workspaceID, hasWorkspace := session.LoginWorkspaceID()
	if !hasWorkspace {
		return Page{}, ErrUnauthenticated
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return Page{}, ErrUnauthenticated
	}
	result, err := service.reader.ReadManagementScopes(ctx, session, after, limit+1, now)
	if err != nil {
		return Page{}, err
	}
	if result.WorkspaceID != workspaceID || !validDisplayName(result.WorkspaceDisplayName) ||
		len(result.Scopes) > limit+1 {
		return Page{}, ErrInvalidResult
	}
	for index, scope := range result.Scopes {
		if !scope.IsValid() ||
			(index > 0 && result.Scopes[index-1].NetworkID().String() >= scope.NetworkID().String()) ||
			(after.IsValid() && scope.NetworkID().String() <= after.String()) {
			return Page{}, ErrInvalidResult
		}
	}
	page := Page{
		workspaceID: workspaceID, workspaceDisplayName: result.WorkspaceDisplayName,
		items: append([]ManagementScope(nil), result.Scopes...),
	}
	if len(page.items) > limit {
		page.items = page.items[:limit]
		page.next = page.items[len(page.items)-1].NetworkID()
	}
	return page, nil
}

func validDisplayName(value string) bool {
	return value != "" && len(value) <= maximumDisplayNameBytes &&
		strings.TrimSpace(value) == value && utf8.ValidString(value)
}
