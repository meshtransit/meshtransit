package ipam

import "net/netip"

const (
	// MaxAliasExcludedPrefixes bounds the complete configured prefix snapshot.
	MaxAliasExcludedPrefixes = 4096
	// MaxAliasExcludedAddresses bounds all address exclusions before deduplication.
	MaxAliasExcludedAddresses = 65536
)

// DeviceAliasAllocationParams is one caller-owned, authoritative exclusion
// snapshot. The caller must load it under the durable Federation Realm lock.
// InUse includes ordinary leases and active aliases; Quarantined includes every
// unreleased alias; Reserved includes DNS and other reserved host addresses.
// ExcludedPrefixes includes all configured overlay/service pools. No field is
// inferred from Redis, client claims, time passage or an allocation default.
// CandidateLimit bounds each of at most four individual host searches.
type DeviceAliasAllocationParams struct {
	IPv4Pool         netip.Prefix
	IPv6Pool         netip.Prefix
	ExcludedPrefixes []netip.Prefix
	InUse            []netip.Addr
	Quarantined      []netip.Addr
	Reserved         []netip.Addr
	CandidateLimit   int
}

// DeviceAliases proposes two distinct host aliases for each explicitly
// requested family. It carries no ownership, lease, membership or packet grant.
// A durable use case must bind the proposal to exact contract/Node generations
// and persist both families, uniqueness, revisions, audit and outbox atomically.
type DeviceAliases struct {
	ResourceIPv4       netip.Addr
	ConsumerSourceIPv4 netip.Addr
	ResourceIPv6       netip.Addr
	ConsumerSourceIPv6 netip.Addr
}

// NextDeviceAliases returns the lowest usable complete alias pair from explicit
// pools. Any invalid or exhausted family returns a zero proposal. A proposal
// cannot be published without durable ownership checks; uniqueness constraints
// remain the concurrency arbiter. Inputs are never modified.
func NextDeviceAliases(params DeviceAliasAllocationParams) (DeviceAliases, error) {
	if !validDeviceAliasAllocation(params) {
		return DeviceAliases{}, ErrInvalidAllocation
	}
	used := make(map[netip.Addr]struct{}, len(params.InUse)+len(params.Quarantined)+len(params.Reserved))
	for _, addresses := range [][]netip.Addr{params.InUse, params.Quarantined, params.Reserved} {
		for _, address := range addresses {
			if !address.IsValid() || address.Is4In6() || address.Zone() != "" {
				return DeviceAliases{}, ErrInvalidAllocation
			}
			used[address] = struct{}{}
		}
	}
	var result DeviceAliases
	for _, family := range []struct {
		pool               netip.Prefix
		resource, consumer *netip.Addr
	}{
		{pool: params.IPv4Pool, resource: &result.ResourceIPv4, consumer: &result.ConsumerSourceIPv4},
		{pool: params.IPv6Pool, resource: &result.ResourceIPv6, consumer: &result.ConsumerSourceIPv6},
	} {
		if !family.pool.IsValid() {
			continue
		}
		occupied := make([]netip.Addr, 0)
		for address := range used {
			if family.pool.Contains(address) {
				occupied = append(occupied, address)
			}
		}
		first, err := NextAvailableAddress(family.pool, occupied, params.CandidateLimit)
		if err != nil {
			return DeviceAliases{}, err
		}
		occupied = append(occupied, first)
		if len(occupied) > params.CandidateLimit {
			return DeviceAliases{}, ErrAddressExhausted
		}
		second, err := NextAvailableAddress(family.pool, occupied, params.CandidateLimit)
		if err != nil {
			return DeviceAliases{}, err
		}
		*family.resource, *family.consumer = first, second
	}
	return result, nil
}

func validDeviceAliasAllocation(params DeviceAliasAllocationParams) bool {
	if params.CandidateLimit <= 0 || params.CandidateLimit > MaxCandidateLimit ||
		len(params.ExcludedPrefixes) > MaxAliasExcludedPrefixes ||
		len(params.InUse) > MaxAliasExcludedAddresses || len(params.Quarantined) > MaxAliasExcludedAddresses ||
		len(params.Reserved) > MaxAliasExcludedAddresses ||
		len(params.InUse)+len(params.Quarantined)+len(params.Reserved) > MaxAliasExcludedAddresses ||
		params.IPv4Pool == (netip.Prefix{}) && params.IPv6Pool == (netip.Prefix{}) {
		return false
	}
	for _, family := range []struct {
		pool netip.Prefix
		ipv4 bool
	}{
		{pool: params.IPv4Pool, ipv4: true}, {pool: params.IPv6Pool, ipv4: false},
	} {
		if family.pool == (netip.Prefix{}) {
			continue
		}
		if !validDeviceAliasPool(family.pool, family.ipv4) {
			return false
		}
	}
	for _, prefix := range params.ExcludedPrefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
			prefix.Overlaps(params.IPv4Pool) || prefix.Overlaps(params.IPv6Pool) {
			return false
		}
	}
	return true
}

func validDeviceAliasPool(pool netip.Prefix, ipv4 bool) bool {
	address := pool.Addr()
	if !pool.IsValid() || pool != pool.Masked() || address.Is4() != ipv4 || address.Is4In6() ||
		address.Zone() != "" || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	// Validate the whole pool, not only its base address. A globally unicast
	// base can still contain loopback, link-local or multicast hosts.
	for _, value := range []string{
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "fe80::/10", "ff00::/8", "::ffff:0:0/96",
	} {
		unsafePrefix, err := netip.ParsePrefix(value)
		if err != nil || pool.Overlaps(unsafePrefix) {
			return false
		}
	}
	return true
}
