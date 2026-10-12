package networkmap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// AliasRole fixes which endpoint may originate flows.
type AliasRole string

const (
	AliasConsumer AliasRole = "consumer"
	AliasProvider AliasRole = "provider"
)

// AliasService is one intersected transport grant. ICMP echo uses zero ports.
type AliasService struct {
	Protocol uint8
	PortFrom uint16
	PortTo   uint16
}

// AliasBinding binds local source translation to one peer and endpoint grant.
// It is ephemeral map authority, never a persistent profile or membership.
type AliasBinding struct {
	ContractID    string
	EndpointID    string
	Generation    uint64
	GrantRevision uint64
	RecoveryEpoch uint64
	SelfKey       string
	PeerKey       string
	Role          AliasRole
	SelfIPv4      netip.Addr
	SelfIPv6      netip.Addr
	ExpiresAt     time.Time
	Services      []AliasService
}

const (
	maxAliasPeers    = 10_000 // matches Core's largest map (MESHTRANSIT_CONTROL_MAP_PEER_LIMIT, at most 10,000)
	maxAliasServices = 64
)

func validateAliases(snapshot Snapshot, now time.Time) error {
	if snapshot.Self.Alias != nil {
		return errors.New("self node cannot carry a peer alias binding")
	}
	occupied := make(map[netip.Addr]struct{})
	for _, node := range append([]Node{snapshot.Self}, snapshot.Peers...) {
		for _, address := range node.Addresses {
			occupied[address.Addr()] = struct{}{}
		}
	}
	owners := make(map[netip.Addr]AliasBinding)
	count := 0
	for _, peer := range snapshot.Peers {
		if peer.Alias == nil {
			continue
		}
		count++
		if count > maxAliasPeers {
			return errors.New("alias peer count exceeds profile limit")
		}
		binding := *peer.Alias
		if err := validateAliasBinding(snapshot.Self, peer, binding, now); err != nil {
			return err
		}
		for _, address := range []netip.Addr{binding.SelfIPv4, binding.SelfIPv6} {
			if !address.IsValid() {
				continue
			}
			if _, exists := occupied[address]; exists {
				return errors.New("local alias collides with mapped address")
			}
			if owner, exists := owners[address]; exists {
				sameProviderEndpoint := binding.Role == AliasProvider && owner.Role == AliasProvider &&
					binding.ContractID == owner.ContractID && binding.EndpointID == owner.EndpointID &&
					binding.Generation == owner.Generation && binding.RecoveryEpoch == owner.RecoveryEpoch
				if !sameProviderEndpoint {
					return errors.New("local alias has incompatible endpoint owners")
				}
			}
			owners[address] = binding
		}
	}
	return nil
}

func validateAliasBinding(self, peer Node, binding AliasBinding, now time.Time) error {
	identityValid := validAliasID(binding.ContractID) && validAliasID(binding.EndpointID) &&
		binding.Generation != 0 && binding.GrantRevision != 0 && binding.RecoveryEpoch != 0 &&
		binding.SelfKey == self.PublicKey && binding.PeerKey == peer.PublicKey
	roleValid := binding.Role == AliasConsumer || binding.Role == AliasProvider
	if !identityValid || !roleValid {
		return errors.New("alias identity, generation or direction is invalid")
	}
	expiryValid := !self.KeyExpiry.IsZero() && !peer.KeyExpiry.IsZero() &&
		!binding.ExpiresAt.IsZero() && binding.ExpiresAt.After(now) &&
		!binding.ExpiresAt.After(self.KeyExpiry) && !binding.ExpiresAt.After(peer.KeyExpiry)
	if !expiryValid || peer.Expired || !peer.MachineAuthorized {
		return errors.New("alias deadline or peer authority is invalid")
	}
	if len(peer.Addresses) == 0 || len(peer.Addresses) > 2 ||
		len(peer.AllowedIPs) != len(peer.Addresses) {
		return errors.New("alias peer must have only exact family host routes")
	}
	families := make(map[bool]bool, 2)
	for _, prefix := range peer.Addresses {
		address := prefix.Addr()
		if families[address.Is4()] || !validAliasAddress(address) {
			return errors.New("alias peer address family is invalid or duplicated")
		}
		families[address.Is4()] = true
	}
	if !slices.Equal(peer.Addresses, peer.AllowedIPs) {
		return errors.New("alias peer routes differ from addresses")
	}
	for _, family := range []struct {
		ipv4  bool
		alias netip.Addr
	}{{ipv4: true, alias: binding.SelfIPv4}, {ipv4: false, alias: binding.SelfIPv6}} {
		if families[family.ipv4] != family.alias.IsValid() {
			return errors.New("alias family support is incomplete")
		}
		if !family.alias.IsValid() {
			continue
		}
		if !validAliasAddress(family.alias) || family.alias.Is4() != family.ipv4 ||
			!validAliasAddress(canonicalAliasFamily(self, family.ipv4)) {
			return errors.New("local alias address or canonical family is invalid")
		}
	}
	if len(binding.Services) == 0 || len(binding.Services) > maxAliasServices {
		return errors.New("alias service count is invalid")
	}
	var previous AliasService
	for index, service := range binding.Services {
		if err := validateAliasService(service, families); err != nil {
			return err
		}
		if index > 0 && (service.Protocol < previous.Protocol ||
			(service.Protocol == previous.Protocol && service.PortFrom <= previous.PortTo)) {
			return errors.New("alias services must be ordered and disjoint")
		}
		previous = service
	}
	return nil
}

func validateAliasService(service AliasService, families map[bool]bool) error {
	switch service.Protocol {
	case 6, 17:
		if service.PortFrom == 0 || service.PortFrom > service.PortTo {
			return errors.New("alias transport port range is invalid")
		}
	case 1, 58:
		ipv4 := service.Protocol == 1
		if service.PortFrom != 0 || service.PortTo != 0 || !families[ipv4] {
			return errors.New("alias icmp service does not match its address family")
		}
	default:
		return errors.New("alias service protocol is unsupported")
	}
	return nil
}

func canonicalAliasFamily(self Node, ipv4 bool) netip.Addr {
	var result netip.Addr
	for _, prefix := range self.Addresses {
		address := prefix.Addr()
		if address.Is4() == ipv4 {
			if result.IsValid() {
				return netip.Addr{}
			}
			result = address
		}
	}
	return result
}

func validAliasAddress(address netip.Addr) bool {
	return address.IsValid() && !address.Is4In6() && address.Zone() == "" &&
		address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func validAliasID(value string) bool {
	if len(value) != 36 {
		return false
	}
	nonzero := false
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
		nonzero = nonzero || char != '0'
	}
	return nonzero
}

// EqualAlias reports exact packet authority equality, excluding pointer identity.
func EqualAlias(left, right *AliasBinding) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	l, r := *left, *right
	l.Services, r.Services = nil, nil
	return l.ContractID == r.ContractID && l.EndpointID == r.EndpointID &&
		l.Generation == r.Generation && l.GrantRevision == r.GrantRevision &&
		l.RecoveryEpoch == r.RecoveryEpoch && l.SelfKey == r.SelfKey && l.PeerKey == r.PeerKey &&
		l.Role == r.Role && l.SelfIPv4 == r.SelfIPv4 && l.SelfIPv6 == r.SelfIPv6 &&
		l.ExpiresAt.Equal(r.ExpiresAt) && slices.Equal(left.Services, right.Services)
}

// ValidateAliasAdvance rejects regression or mutation of the same endpoint
// grant. A policy or alias change needs a newer grant revision. Recovery cannot
// replace the epoch of an existing contract.
func ValidateAliasAdvance(previous, next *AliasBinding) error {
	if previous != nil && next == nil {
		return errors.New("networkmap: alias cannot downgrade to an ordinary peer")
	}
	if previous == nil {
		return nil
	}
	if previous.ContractID == next.ContractID && (previous.Role != next.Role ||
		previous.RecoveryEpoch != next.RecoveryEpoch) {
		return errors.New("networkmap: alias contract authority changed")
	}
	if previous.EndpointID != next.EndpointID {
		return nil
	}
	if previous.ContractID != next.ContractID || previous.RecoveryEpoch != next.RecoveryEpoch ||
		previous.Role != next.Role ||
		next.Generation < previous.Generation || next.GrantRevision < previous.GrantRevision {
		return errors.New("networkmap: alias authority regressed")
	}
	identityUnchanged := [2]string{previous.SelfKey, previous.PeerKey} == [2]string{next.SelfKey, next.PeerKey}
	if previous.Generation == next.Generation && (!identityUnchanged ||
		previous.SelfIPv4 != next.SelfIPv4 || previous.SelfIPv6 != next.SelfIPv6) {
		return errors.New("networkmap: alias generation binding changed")
	}
	if previous.Generation == next.Generation && previous.GrantRevision == next.GrantRevision &&
		!EqualAlias(previous, next) {
		return fmt.Errorf("%w: same alias grant changed", ErrInvalid)
	}
	return nil
}

func cloneAlias(binding *AliasBinding) *AliasBinding {
	if binding == nil {
		return nil
	}
	cloned := *binding
	cloned.Services = slices.Clone(binding.Services)
	return &cloned
}
