// Package provisioning owns Network creation inside a Workspace (ADR-050
// implementation step 5b). PostgreSQL checks network.create, the Workspace
// pools and prefix overlap; this package validates shapes and receipts and
// never retries an uncertain commit.
package provisioning

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
	"github.com/meshtransit/meshtransit/internal/workspace/settings"
)

var (
	// ErrInvalid reports a malformed request or durable result.
	ErrInvalid = errors.New("network provisioning: invalid request or result")
	// ErrForbidden conceals missing network.create authority.
	ErrForbidden = errors.New("network provisioning: permission denied")
	// ErrPrefixOutsidePool reports a prefix outside the Workspace overlay pools.
	ErrPrefixOutsidePool = errors.New("network provisioning: prefix outside the Workspace pools")
	// ErrPrefixOverlap reports a prefix that overlaps another Network in the Workspace.
	ErrPrefixOverlap = errors.New("network provisioning: prefix overlaps another Network")
	// ErrConflict reports a reused Network ID or a name already used in the Workspace.
	ErrConflict = errors.New("network provisioning: conflict")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("network provisioning: unavailable")
)

// Prefix length bounds; PostgreSQL enforces the same.
const (
	MinIPv4Bits = 16
	MaxIPv4Bits = 28
	MinIPv6Bits = 56
	MaxIPv6Bits = 112
)

// OverlayIPv4Range contains every Network IPv4 prefix.
var OverlayIPv4Range = netip.MustParsePrefix("100.64.0.0/10")

// ValidIPv4Prefix reports a canonical, correctly sized prefix inside
// OverlayIPv4Range.
func ValidIPv4Prefix(ipv4 netip.Prefix) bool {
	return ipv4.IsValid() && ipv4.Addr().Is4() && ipv4 == ipv4.Masked() &&
		OverlayIPv4Range.Contains(ipv4.Addr()) && ipv4.Bits() >= OverlayIPv4Range.Bits() &&
		ipv4.Bits() >= MinIPv4Bits && ipv4.Bits() <= MaxIPv4Bits
}

// ValidIPv6Prefix reports a canonical, correctly sized native IPv6 prefix.
func ValidIPv6Prefix(ipv6 netip.Prefix) bool {
	return ipv6.IsValid() && ipv6.Addr().Is6() && !ipv6.Addr().Is4In6() && ipv6 == ipv6.Masked() &&
		ipv6.Bits() >= MinIPv6Bits && ipv6.Bits() <= MaxIPv6Bits
}

// ValidPrefixes reports a valid IPv4 prefix and either a valid IPv6 prefix or
// none; with none, PostgreSQL assigns the first free /64 of the Workspace pool.
func ValidPrefixes(ipv4, ipv6 netip.Prefix) bool {
	return ValidIPv4Prefix(ipv4) && (ipv6 == netip.Prefix{} || ValidIPv6Prefix(ipv6))
}

// Command creates one Network in the Session's login Workspace. NetworkID is
// client-chosen so a retried request converges on one Network.
type Command struct {
	Session     accountsession.Session
	WorkspaceID workspace.ID
	NetworkID   network.ID
	DisplayName string
	IPv4Prefix  netip.Prefix
	// IPv6Prefix is optional; the zero value asks Core to assign one.
	IPv6Prefix    netip.Prefix
	CorrelationID publicid.ID
}

// IsValid checks shape and binds the request to the login Workspace.
func (command Command) IsValid() bool {
	login, ok := command.Session.LoginWorkspaceID()
	return command.Session.IsValid() && ok && login == command.WorkspaceID && command.WorkspaceID.IsValid() &&
		command.NetworkID.IsValid() && settings.ValidName(command.DisplayName) &&
		ValidPrefixes(command.IPv4Prefix, command.IPv6Prefix) && command.CorrelationID.IsValid()
}

// Result is the durable Network with its committed prefixes; Replayed
// reports an earlier commit.
type Result struct {
	NetworkID   network.ID
	DisplayCode identity.DisplayCode
	IPv4Prefix  netip.Prefix
	IPv6Prefix  netip.Prefix
	Version     int64
	CreatedAt   time.Time
	Replayed    bool
}

// matches reports a receipt for this command: the same Network and IPv4
// prefix, and the requested IPv6 prefix or a valid assigned one.
func (result Result) matches(command Command) bool {
	return result.NetworkID == command.NetworkID && result.DisplayCode.IsValid() && result.Version > 0 &&
		!result.CreatedAt.IsZero() && result.IPv4Prefix == command.IPv4Prefix && ValidIPv6Prefix(result.IPv6Prefix) &&
		(command.IPv6Prefix == netip.Prefix{} || result.IPv6Prefix == command.IPv6Prefix)
}

// Store commits with fresh authority and audit evidence.
type Store interface {
	Create(context.Context, Command) (Result, error)
}

// Clock supplies the application admission instant.
type Clock interface{ Now() time.Time }

// Service validates requests and receipts.
type Service struct {
	store Store
	clock Clock
}

// NewService validates explicit dependencies.
func NewService(store Store, clock Clock) (*Service, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock}, nil
}

// Create admits an active Session and returns the durable Network.
func (service *Service) Create(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil || !command.IsValid() {
		return Result{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !command.Session.IsActiveAt(now) {
		return Result{}, ErrForbidden
	}
	result, err := service.store.Create(ctx, command)
	if err != nil {
		return Result{}, err
	}
	if !result.matches(command) {
		return Result{}, ErrInvalid
	}
	return result, nil
}
