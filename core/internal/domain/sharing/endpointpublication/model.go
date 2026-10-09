// Package endpointpublication owns the fail-closed route reconciliation model
// for Resource Sharing Private Endpoints.
package endpointpublication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

const maximumTargetAddresses = 2

var (
	// ErrInvalidCandidate reports malformed non-authoritative polling hints.
	ErrInvalidCandidate = errors.New("private endpoint publication: invalid candidate")
	// ErrInvalidSnapshot reports incomplete or inconsistent exact authority.
	ErrInvalidSnapshot = errors.New("private endpoint publication: invalid snapshot")
	// ErrInvalidRoute reports an unsafe gateway route specification.
	ErrInvalidRoute = errors.New("private endpoint publication: invalid route")
)

// Candidate is a bounded polling hint. The exact snapshot must be reread
// before any gateway effect.
type Candidate struct {
	EndpointID sharing.PrivateEndpointID
	Generation int64
}

// IsValid reports whether the hint carries a usable identity and generation.
func (candidate Candidate) IsValid() bool {
	return candidate.EndpointID.IsValid() && candidate.Generation > 0
}

// Scope is one public Workspace and Network routing boundary.
type Scope struct {
	WorkspaceID workspace.ID `json:"workspace_id"`
	NetworkID   network.ID   `json:"network_id"`
}

// IsValid reports whether both public scope identities are present.
func (scope Scope) IsValid() bool {
	return scope.WorkspaceID.IsValid() && scope.NetworkID.IsValid()
}

// PortRange is one inclusive gateway destination-port interval.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// TrafficConstraint is one explicitly supported protocol grant.
type TrafficConstraint struct {
	Protocol              string      `json:"protocol"`
	DestinationPortRanges []PortRange `json:"destination_port_ranges"`
}

// Snapshot is an exact PostgreSQL-authoritative publication read. Revision and
// audit heads are optimistic concurrency evidence, never gateway input.
type Snapshot struct {
	DeploymentID            deployment.ID
	EndpointID              sharing.PrivateEndpointID
	EndpointVersion         int64
	EndpointGeneration      int64
	AliasLeaseVersion       int64
	ContractVersion         int64
	ImportedResourceVersion int64
	ProviderScope           Scope
	ConsumerScope           Scope
	TargetDeviceID          publicid.ID
	TargetGeneration        int64
	TargetAddresses         []netip.Addr
	ResourceAlias           netip.Addr
	AccessName              sharing.AccessName
	Traffic                 []TrafficConstraint
	ConstraintHash          [sha256.Size]byte
	ExpiresAt               time.Time
	SnapshotAt              time.Time
	ProviderNetworkRevision int64
	ProviderDNSRevision     int64
	ProviderRouteRevision   int64
	ProviderSharingRevision int64
	ConsumerNetworkRevision int64
	ConsumerDNSRevision     int64
	ConsumerRouteRevision   int64
	ConsumerSharingRevision int64
	ProviderStreamID        int64
	ProviderStreamSequence  int64
	ProviderStreamHash      [sha256.Size]byte
	ConsumerStreamID        int64
	ConsumerStreamSequence  int64
	ConsumerStreamHash      [sha256.Size]byte
}

// IsValid rejects stale, ambiguous, or non-canonical gateway authority.
func (snapshot Snapshot) IsValid() bool {
	if !snapshot.DeploymentID.IsValid() || !snapshot.EndpointID.IsValid() ||
		snapshot.EndpointVersion != 1 || snapshot.EndpointGeneration <= 0 ||
		snapshot.AliasLeaseVersion != 1 || snapshot.ContractVersion <= 0 ||
		snapshot.ImportedResourceVersion <= 0 || !snapshot.ProviderScope.IsValid() ||
		!snapshot.ConsumerScope.IsValid() || snapshot.ProviderScope == snapshot.ConsumerScope ||
		!snapshot.TargetDeviceID.IsValid() || snapshot.TargetGeneration <= 0 ||
		!validAddresses(snapshot.TargetAddresses) || !validAlias(snapshot.ResourceAlias) ||
		!snapshot.AccessName.IsValid() || !validTraffic(snapshot.Traffic) ||
		snapshot.ConstraintHash == ([sha256.Size]byte{}) || !canonicalTime(snapshot.ExpiresAt) ||
		!canonicalTime(snapshot.SnapshotAt) || !snapshot.SnapshotAt.Before(snapshot.ExpiresAt) {
		return false
	}
	for _, revision := range []int64{
		snapshot.ProviderNetworkRevision, snapshot.ProviderDNSRevision,
		snapshot.ProviderRouteRevision, snapshot.ProviderSharingRevision,
		snapshot.ConsumerNetworkRevision, snapshot.ConsumerDNSRevision,
		snapshot.ConsumerRouteRevision, snapshot.ConsumerSharingRevision,
		snapshot.ProviderStreamID, snapshot.ProviderStreamSequence,
		snapshot.ConsumerStreamID, snapshot.ConsumerStreamSequence,
	} {
		if revision <= 0 {
			return false
		}
	}
	return snapshot.ProviderStreamID != snapshot.ConsumerStreamID
}

// Route is the complete idempotent desired state submitted to the trusted
// gateway. It contains no database-internal identifiers.
type Route struct {
	DeploymentID       string              `json:"deployment_id"`
	EndpointID         string              `json:"endpoint_id"`
	EndpointGeneration int64               `json:"endpoint_generation"`
	ProviderScope      routeScope          `json:"provider_scope"`
	ConsumerScope      routeScope          `json:"consumer_scope"`
	TargetDeviceID     string              `json:"target_device_id"`
	TargetGeneration   int64               `json:"target_generation"`
	TargetAddresses    []string            `json:"target_addresses"`
	ResourceAlias      string              `json:"resource_alias"`
	AccessName         string              `json:"access_name"`
	Traffic            []TrafficConstraint `json:"traffic"`
	ConstraintHash     string              `json:"constraint_hash"`
	ExpiresAt          time.Time           `json:"expires_at"`
}

type routeScope struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
}

// Route returns a caller-owned canonical gateway specification.
func (snapshot Snapshot) Route() (Route, error) {
	if !snapshot.IsValid() {
		return Route{}, ErrInvalidSnapshot
	}
	targets := make([]string, len(snapshot.TargetAddresses))
	for index, address := range snapshot.TargetAddresses {
		targets[index] = address.String()
	}
	return Route{
		DeploymentID: snapshot.DeploymentID.String(), EndpointID: snapshot.EndpointID.String(),
		EndpointGeneration: snapshot.EndpointGeneration,
		ProviderScope:      routeScope{WorkspaceID: snapshot.ProviderScope.WorkspaceID.String(), NetworkID: snapshot.ProviderScope.NetworkID.String()},
		ConsumerScope:      routeScope{WorkspaceID: snapshot.ConsumerScope.WorkspaceID.String(), NetworkID: snapshot.ConsumerScope.NetworkID.String()},
		TargetDeviceID:     snapshot.TargetDeviceID.String(), TargetGeneration: snapshot.TargetGeneration,
		TargetAddresses: targets, ResourceAlias: snapshot.ResourceAlias.String(),
		AccessName: snapshot.AccessName.String(), Traffic: cloneTraffic(snapshot.Traffic),
		ConstraintHash: hex.EncodeToString(snapshot.ConstraintHash[:]), ExpiresAt: snapshot.ExpiresAt,
	}, nil
}

// Hash returns the deterministic proof bound to the exact desired route.
func (route Route) Hash() ([sha256.Size]byte, error) {
	if !route.isValid() {
		return [sha256.Size]byte{}, ErrInvalidRoute
	}
	encoded, err := json.Marshal(route)
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidRoute
	}
	return sha256.Sum256(encoded), nil
}

func (route Route) isValid() bool {
	deploymentID, deploymentErr := deployment.ParseID(route.DeploymentID)
	endpointID, endpointErr := sharing.ParsePrivateEndpointID(route.EndpointID)
	providerWorkspace, providerWorkspaceErr := workspace.ParseID(route.ProviderScope.WorkspaceID)
	providerNetwork, providerNetworkErr := network.ParseID(route.ProviderScope.NetworkID)
	consumerWorkspace, consumerWorkspaceErr := workspace.ParseID(route.ConsumerScope.WorkspaceID)
	consumerNetwork, consumerNetworkErr := network.ParseID(route.ConsumerScope.NetworkID)
	target, targetErr := publicid.Parse(route.TargetDeviceID)
	alias, aliasErr := netip.ParseAddr(route.ResourceAlias)
	name, nameErr := sharing.ParseAccessName(route.AccessName)
	hash, hashErr := decodeHash(route.ConstraintHash)
	addresses, addressErr := parseAddresses(route.TargetAddresses)
	return deploymentErr == nil && deploymentID.IsValid() && endpointErr == nil && endpointID.IsValid() &&
		providerWorkspaceErr == nil && providerNetworkErr == nil && consumerWorkspaceErr == nil &&
		consumerNetworkErr == nil && providerWorkspace.IsValid() && providerNetwork.IsValid() &&
		consumerWorkspace.IsValid() && consumerNetwork.IsValid() &&
		(providerWorkspace != consumerWorkspace || providerNetwork != consumerNetwork) &&
		targetErr == nil && target.IsValid() && route.EndpointGeneration > 0 && route.TargetGeneration > 0 &&
		aliasErr == nil && validAlias(alias) && nameErr == nil && name.IsValid() && hashErr == nil &&
		hash != ([sha256.Size]byte{}) && addressErr == nil && validAddresses(addresses) &&
		validTraffic(route.Traffic) && canonicalTime(route.ExpiresAt)
}

// WithdrawalReason is the only automatic terminal classification.
type WithdrawalReason string

const (
	// WithdrawalExpired reports exclusive endpoint or contract expiry.
	WithdrawalExpired WithdrawalReason = "expired"
	// WithdrawalInvalidated reports drift in the pinned authority chain.
	WithdrawalInvalidated WithdrawalReason = "invalidated"
)

// WithdrawalSnapshot is exact terminalization authority read after PostgreSQL
// decides that an endpoint is expired or no longer matches its authority chain.
type WithdrawalSnapshot struct {
	DeploymentID            deployment.ID
	EndpointID              sharing.PrivateEndpointID
	EndpointVersion         int64
	EndpointGeneration      int64
	AliasLeaseVersion       int64
	ContractVersion         int64
	ImportedResourceVersion int64
	AccessNameVersion       int64
	DNSPublicationVersion   int64
	ResourceAlias           netip.Addr
	RouteSnapshotHash       [sha256.Size]byte
	RoutePresent            bool
	Reason                  WithdrawalReason
	SnapshotAt              time.Time
	ProviderNetworkRevision int64
	ProviderDNSRevision     int64
	ProviderRouteRevision   int64
	ProviderSharingRevision int64
	ConsumerNetworkRevision int64
	ConsumerDNSRevision     int64
	ConsumerRouteRevision   int64
	ConsumerSharingRevision int64
	ProviderStreamID        int64
	ProviderStreamSequence  int64
	ProviderStreamHash      [sha256.Size]byte
	ConsumerStreamID        int64
	ConsumerStreamSequence  int64
	ConsumerStreamHash      [sha256.Size]byte
}

// IsValid checks the complete terminal CAS and audit vector.
func (snapshot WithdrawalSnapshot) IsValid() bool {
	if !snapshot.DeploymentID.IsValid() || !snapshot.EndpointID.IsValid() ||
		snapshot.EndpointVersion <= 0 || snapshot.EndpointGeneration <= 0 ||
		snapshot.AliasLeaseVersion <= 0 || snapshot.ContractVersion <= 0 ||
		snapshot.ImportedResourceVersion <= 0 || snapshot.AccessNameVersion <= 0 ||
		snapshot.DNSPublicationVersion < 0 || !validAlias(snapshot.ResourceAlias) ||
		snapshot.Reason != WithdrawalExpired && snapshot.Reason != WithdrawalInvalidated ||
		snapshot.RoutePresent == (snapshot.RouteSnapshotHash == ([sha256.Size]byte{})) ||
		snapshot.DNSPublicationVersion > 0 && !snapshot.RoutePresent ||
		!canonicalTime(snapshot.SnapshotAt) {
		return false
	}
	for _, value := range []int64{
		snapshot.ProviderNetworkRevision, snapshot.ProviderDNSRevision,
		snapshot.ProviderRouteRevision, snapshot.ProviderSharingRevision,
		snapshot.ConsumerNetworkRevision, snapshot.ConsumerDNSRevision,
		snapshot.ConsumerRouteRevision, snapshot.ConsumerSharingRevision,
		snapshot.ProviderStreamID, snapshot.ProviderStreamSequence,
		snapshot.ConsumerStreamID, snapshot.ConsumerStreamSequence,
	} {
		if value <= 0 {
			return false
		}
	}
	return snapshot.ProviderStreamID != snapshot.ConsumerStreamID
}

// Withdrawal is an idempotent route-removal command. Its hash proves which
// previously applied route is being removed.
type Withdrawal struct {
	DeploymentID       string `json:"deployment_id"`
	EndpointID         string `json:"endpoint_id"`
	EndpointGeneration int64  `json:"endpoint_generation"`
	ResourceAlias      string `json:"resource_alias"`
	RouteSnapshotHash  string `json:"route_snapshot_hash"`
	RoutePresent       bool   `json:"route_present"`
	Reason             string `json:"reason"`
}

// Withdrawal returns the canonical gateway removal command.
func (snapshot WithdrawalSnapshot) Withdrawal() (Withdrawal, error) {
	if !snapshot.IsValid() {
		return Withdrawal{}, ErrInvalidSnapshot
	}
	return Withdrawal{
		DeploymentID: snapshot.DeploymentID.String(), EndpointID: snapshot.EndpointID.String(),
		EndpointGeneration: snapshot.EndpointGeneration, ResourceAlias: snapshot.ResourceAlias.String(),
		RouteSnapshotHash: hex.EncodeToString(snapshot.RouteSnapshotHash[:]),
		RoutePresent:      snapshot.RoutePresent, Reason: string(snapshot.Reason),
	}, nil
}

// TerminalHash binds evidence to the exact route generation and DB-selected reason.
func (snapshot WithdrawalSnapshot) TerminalHash() ([sha256.Size]byte, error) {
	withdrawal, err := snapshot.Withdrawal()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return withdrawal.Hash()
}

// Hash validates and hashes the canonical route-removal command.
func (withdrawal Withdrawal) Hash() ([sha256.Size]byte, error) {
	deploymentID, deploymentErr := deployment.ParseID(withdrawal.DeploymentID)
	endpointID, endpointErr := sharing.ParsePrivateEndpointID(withdrawal.EndpointID)
	alias, aliasErr := netip.ParseAddr(withdrawal.ResourceAlias)
	routeHash, routeHashErr := decodeHash(withdrawal.RouteSnapshotHash)
	if deploymentErr != nil || !deploymentID.IsValid() || endpointErr != nil || !endpointID.IsValid() ||
		withdrawal.EndpointGeneration <= 0 || aliasErr != nil || !validAlias(alias) ||
		routeHashErr != nil || withdrawal.RoutePresent == (routeHash == ([sha256.Size]byte{})) ||
		withdrawal.Reason != string(WithdrawalExpired) &&
			withdrawal.Reason != string(WithdrawalInvalidated) {
		return [sha256.Size]byte{}, ErrInvalidRoute
	}
	encoded, err := json.Marshal(withdrawal)
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidRoute
	}
	return sha256.Sum256(encoded), nil
}

func validAddresses(addresses []netip.Addr) bool {
	if len(addresses) == 0 || len(addresses) > maximumTargetAddresses ||
		!slices.IsSortedFunc(addresses, compareAddresses) {
		return false
	}
	for index, address := range addresses {
		if !address.IsValid() || !address.IsGlobalUnicast() || address.Is4In6() || address.Zone() != "" ||
			index > 0 && address == addresses[index-1] {
			return false
		}
	}
	return true
}

func compareAddresses(left, right netip.Addr) int { return left.Compare(right) }

func validAlias(alias netip.Addr) bool {
	return alias.IsValid() && alias.IsGlobalUnicast() && !alias.Is4In6() && alias.Zone() == ""
}

func validTraffic(values []TrafficConstraint) bool {
	if len(values) == 0 || len(values) > 3 {
		return false
	}
	order := map[string]int{"tcp": 1, "udp": 2, "icmp": 3}
	previous := 0
	for _, value := range values {
		current := order[value.Protocol]
		if current <= previous {
			return false
		}
		previous = current
		if value.Protocol == "icmp" {
			if len(value.DestinationPortRanges) != 0 {
				return false
			}
			continue
		}
		if len(value.DestinationPortRanges) == 0 || len(value.DestinationPortRanges) > 64 {
			return false
		}
		var last uint16
		for index, portRange := range value.DestinationPortRanges {
			if portRange.First == 0 || portRange.Last < portRange.First ||
				index > 0 && portRange.First <= last+boolToUint16(last != ^uint16(0)) {
				return false
			}
			last = portRange.Last
		}
	}
	return true
}

func boolToUint16(value bool) uint16 {
	if value {
		return 1
	}
	return 0
}

func cloneTraffic(values []TrafficConstraint) []TrafficConstraint {
	result := make([]TrafficConstraint, len(values))
	for index, value := range values {
		result[index] = TrafficConstraint{Protocol: value.Protocol, DestinationPortRanges: slices.Clone(value.DestinationPortRanges)}
	}
	return result
}

func parseAddresses(values []string) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, len(values))
	for index, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || address.String() != value {
			return nil, ErrInvalidSnapshot
		}
		addresses[index] = address
	}
	return addresses, nil
}

func decodeHash(value string) ([sha256.Size]byte, error) {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return [sha256.Size]byte{}, ErrInvalidSnapshot
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidSnapshot
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result, nil
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 &&
		value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}
