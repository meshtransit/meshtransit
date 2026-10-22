package networkmap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/client/internal/overlayframe"
)

const (
	maxPeers             = 100_000
	maxNodeAddresses     = 16
	maxNodeAllowedIPs    = 1_024
	maxNodeEndpoints     = 128
	maxPolicyRules       = 100_000
	maxRuleSources       = 1_024
	maxRuleDestinations  = 4_096
	maxRelayRegions      = 1_024
	maxRelayNodes        = 32
	maxDNSResolvers      = 32
	maxDNSRoutes         = 512
	maxDNSRouteResolvers = 32
	maxDNSSearchDomains  = 64
	maxDNSRecords        = 50_000 // mtcp-v1 §7.3: A and AAAA for self, 10,000 peers and 10,000 shares fit
	maxNameRunes         = 253
	maxStableIDBytes     = 128
	maxCapabilityBytes   = 512
)

var ErrInvalid = errors.New("networkmap: invalid snapshot")

// ValidateAndClone verifies all security-relevant invariants and returns a
// defensive copy suitable for atomic publication.
func ValidateAndClone(snapshot Snapshot, now time.Time) (Snapshot, error) {
	if snapshot.Revision == 0 {
		return Snapshot{}, fmt.Errorf("%w: revision must be non-zero", ErrInvalid)
	}
	if len(snapshot.Peers) > maxPeers {
		return Snapshot{}, fmt.Errorf("%w: peer count exceeds %d", ErrInvalid, maxPeers)
	}
	if len(snapshot.Policy) > maxPolicyRules {
		return Snapshot{}, fmt.Errorf("%w: policy rule count exceeds %d", ErrInvalid, maxPolicyRules)
	}
	if len(snapshot.Relays) > maxRelayRegions {
		return Snapshot{}, fmt.Errorf("%w: relay region count exceeds %d", ErrInvalid, maxRelayRegions)
	}
	if snapshot.NetworkName != "" {
		if err := validateText("network name", snapshot.NetworkName, maxNameRunes); err != nil {
			return Snapshot{}, err
		}
	}
	if err := validateNode(snapshot.Self, true, now); err != nil {
		return Snapshot{}, fmt.Errorf("%w: self: %w", ErrInvalid, err)
	}
	if snapshot.Audit.Enabled() && snapshot.Audit.NodeID() != snapshot.Self.ID {
		return Snapshot{}, fmt.Errorf("%w: audit credential reporter does not match self", ErrInvalid)
	}

	ids := map[uint64]struct{}{snapshot.Self.ID: {}}
	keys := map[string]struct{}{snapshot.Self.PublicKey: {}}
	addresses := make(map[netip.Addr]uint64)
	if err := addDirectAddresses(addresses, snapshot.Self); err != nil {
		return Snapshot{}, err
	}
	for index, peer := range snapshot.Peers {
		if err := validateNode(peer, false, now); err != nil {
			return Snapshot{}, fmt.Errorf("%w: peer %d: %w", ErrInvalid, index, err)
		}
		if _, exists := ids[peer.ID]; exists {
			return Snapshot{}, fmt.Errorf("%w: duplicate node id %d", ErrInvalid, peer.ID)
		}
		ids[peer.ID] = struct{}{}
		if _, exists := keys[peer.PublicKey]; exists {
			return Snapshot{}, fmt.Errorf("%w: duplicate node public key", ErrInvalid)
		}
		keys[peer.PublicKey] = struct{}{}
		if err := addDirectAddresses(addresses, peer); err != nil {
			return Snapshot{}, err
		}
	}

	if err := validateAliases(snapshot, now); err != nil {
		return Snapshot{}, fmt.Errorf("%w: alias: %w", ErrInvalid, err)
	}

	for index, rule := range snapshot.Policy {
		if err := validateRule(rule); err != nil {
			return Snapshot{}, fmt.Errorf("%w: policy rule %d: %w", ErrInvalid, index, err)
		}
	}
	for id, region := range snapshot.Relays {
		if id != region.ID || id <= 0 {
			return Snapshot{}, fmt.Errorf("%w: relay region key/id mismatch", ErrInvalid)
		}
		if err := validateRelayRegion(region); err != nil {
			return Snapshot{}, fmt.Errorf("%w: relay region %d: %w", ErrInvalid, id, err)
		}
	}
	if snapshot.DNS != nil {
		if err := validateDNSConfig(*snapshot.DNS); err != nil {
			return Snapshot{}, fmt.Errorf("%w: dns: %w", ErrInvalid, err)
		}
	}
	if err := validateServed(snapshot.Served); err != nil {
		return Snapshot{}, fmt.Errorf("%w: served: %w", ErrInvalid, err)
	}
	if err := validateServedExits(snapshot.ServedExits); err != nil {
		return Snapshot{}, fmt.Errorf("%w: served exits: %w", ErrInvalid, err)
	}
	if err := validateExits(snapshot.Exits, snapshot.Self.StableID); err != nil {
		return Snapshot{}, fmt.Errorf("%w: exits: %w", ErrInvalid, err)
	}
	if err := validateExitRoute(snapshot.ExitRoute, snapshot.Exits); err != nil {
		return Snapshot{}, fmt.Errorf("%w: exit route: %w", ErrInvalid, err)
	}
	if err := validateRoutes(snapshot.Routes, snapshot.Self.StableID); err != nil {
		return Snapshot{}, fmt.Errorf("%w: routes: %w", ErrInvalid, err)
	}

	return cloneSnapshot(snapshot), nil
}

func validateDNSConfig(config DNSConfig) error {
	if len(config.Resolvers) > maxDNSResolvers ||
		len(config.FallbackResolvers) > maxDNSResolvers {
		return fmt.Errorf("resolver count exceeds %d", maxDNSResolvers)
	}
	if len(config.Routes) > maxDNSRoutes {
		return fmt.Errorf("route count exceeds %d", maxDNSRoutes)
	}
	if len(config.SearchDomains) > maxDNSSearchDomains {
		return fmt.Errorf("search domain count exceeds %d", maxDNSSearchDomains)
	}
	if len(config.Records) > maxDNSRecords {
		return fmt.Errorf("record count exceeds %d", maxDNSRecords)
	}
	if err := validateDNSResolvers("global", config.Resolvers); err != nil {
		return err
	}
	if err := validateDNSResolvers("fallback", config.FallbackResolvers); err != nil {
		return err
	}

	seenRoutes := make(map[string]struct{}, len(config.Routes))
	for index, route := range config.Routes {
		if !validCanonicalDNSName(route.Suffix, true) {
			return fmt.Errorf("route %d suffix is invalid", index)
		}
		if _, exists := seenRoutes[route.Suffix]; exists {
			return fmt.Errorf("route %d suffix is duplicated", index)
		}
		seenRoutes[route.Suffix] = struct{}{}
		if len(route.Resolvers) > maxDNSRouteResolvers {
			return fmt.Errorf("route %d resolver count exceeds %d", index, maxDNSRouteResolvers)
		}
		if route.Unavailable && len(route.Resolvers) != 0 {
			return fmt.Errorf("route %d is unavailable but has resolvers", index)
		}
		if route.Unavailable && route.Suffix == "." {
			return fmt.Errorf("route %d is an unavailable root", index)
		}
		if err := validateDNSResolvers("route", route.Resolvers); err != nil {
			return fmt.Errorf("route %d: %w", index, err)
		}
	}

	seenDomains := make(map[string]struct{}, len(config.SearchDomains))
	for index, domain := range config.SearchDomains {
		if !validCanonicalDNSName(domain, false) {
			return fmt.Errorf("search domain %d is invalid", index)
		}
		if _, exists := seenDomains[domain]; exists {
			return fmt.Errorf("search domain %d is duplicated", index)
		}
		seenDomains[domain] = struct{}{}
	}

	type recordKey struct {
		name    string
		record  DNSRecordType
		address netip.Addr
	}
	seenRecords := make(map[recordKey]struct{}, len(config.Records))
	for index, record := range config.Records {
		if !validCanonicalDNSName(record.Name, false) {
			return fmt.Errorf("record %d name is invalid", index)
		}
		address := record.Address
		if !address.IsValid() || address.Is4In6() || address.Zone() != "" || address.IsMulticast() {
			return fmt.Errorf("record %d address is invalid", index)
		}
		if (record.Type == DNSRecordA && !address.Is4()) ||
			(record.Type == DNSRecordAAAA && !address.Is6()) ||
			(record.Type != DNSRecordA && record.Type != DNSRecordAAAA) {
			return fmt.Errorf("record %d type does not match its address", index)
		}
		key := recordKey{name: record.Name, record: record.Type, address: address}
		if _, exists := seenRecords[key]; exists {
			return fmt.Errorf("record %d is duplicated", index)
		}
		seenRecords[key] = struct{}{}
	}

	return nil
}

func validateDNSResolvers(kind string, resolvers []DNSResolver) error {
	seen := make(map[netip.AddrPort]struct{}, len(resolvers))
	for index, resolver := range resolvers {
		endpoint := resolver.Address
		address := endpoint.Addr()
		if !endpoint.IsValid() || !validDNSResolverPort(kind, endpoint) || address.Is4In6() ||
			!address.IsGlobalUnicast() || address.IsLoopback() ||
			address.IsLinkLocalUnicast() || address.Zone() != "" {
			return fmt.Errorf("%s resolver %d is invalid or unsupported", kind, index)
		}
		if _, exists := seen[endpoint]; exists {
			return fmt.Errorf("%s resolver %d is duplicated", kind, index)
		}
		seen[endpoint] = struct{}{}
	}

	return nil
}

// validDNSResolverPort accepts port 53, and for a route's resolver in the
// mesh (a resolver Device of a forward zone) also 1024-65535: control never
// points the node's own sockets at another port of a LAN or Internet host.
func validDNSResolverPort(kind string, endpoint netip.AddrPort) bool {
	address := endpoint.Addr()
	return endpoint.Port() == 53 || (kind == "route" && endpoint.Port() >= 1024 &&
		overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())))
}

func validCanonicalDNSName(value string, allowRoot bool) bool {
	if allowRoot && value == "." {
		return true
	}
	return value == strings.ToLower(value) && !strings.HasSuffix(value, ".") &&
		validHostname(value, false)
}

func validateNode(node Node, self bool, now time.Time) error {
	if node.ID == 0 || node.StableID == "" || len(node.StableID) > maxStableIDBytes {
		return errors.New("identity is missing or too long")
	}
	if err := validateText("node name", node.Name, maxNameRunes); err != nil {
		return err
	}
	if !validTypedKey(node.PublicKey, "nodekey:") {
		return errors.New("public key is malformed")
	}
	if node.DiscoveryKey != "" && !validTypedKey(node.DiscoveryKey, "discokey:") {
		return errors.New("discovery key is malformed")
	}
	if len(node.Addresses) == 0 || len(node.Addresses) > maxNodeAddresses {
		return errors.New("direct address count is invalid")
	}
	if len(node.AllowedIPs) == 0 || len(node.AllowedIPs) > maxNodeAllowedIPs {
		return errors.New("allowed ip count is invalid")
	}
	if len(node.Endpoints) > maxNodeEndpoints {
		return errors.New("endpoint count exceeds limit")
	}
	if node.HomeRelay < 0 {
		return errors.New("home relay id is negative")
	}
	for _, prefix := range node.Addresses {
		if !validPrefix(prefix) || prefix.Addr().IsUnspecified() ||
			prefix.Bits() != prefix.Addr().BitLen() {
			return fmt.Errorf("direct address %q is invalid", prefix)
		}
		if !containsPrefix(node.AllowedIPs, prefix) {
			return fmt.Errorf("direct address %q is not allowed", prefix)
		}
	}
	for _, prefix := range node.AllowedIPs {
		if !validPrefix(prefix) {
			return fmt.Errorf("allowed prefix %q is invalid", prefix)
		}
		// Addresses are allowed prefixes, so this bounds them too: a map can
		// never route a LAN, a public range or the default route to a peer.
		if !overlayframe.Contains(prefix) {
			return fmt.Errorf("allowed prefix %q is outside the overlay frame", prefix)
		}
	}
	seenEndpoints := make(map[netip.AddrPort]struct{}, len(node.Endpoints))
	for _, endpoint := range node.Endpoints {
		if !UsableEndpoint(endpoint) {
			return fmt.Errorf("endpoint %q is invalid", endpoint)
		}
		if _, exists := seenEndpoints[endpoint]; exists {
			return fmt.Errorf("endpoint %q is duplicated", endpoint)
		}
		seenEndpoints[endpoint] = struct{}{}
	}
	if self && !node.MachineAuthorized {
		return errors.New("machine is not authorized")
	}
	if self && (node.Expired || (!node.KeyExpiry.IsZero() && !node.KeyExpiry.After(now))) {
		return errors.New("node key is expired")
	}

	return nil
}

func validateRule(rule Rule) error {
	if len(rule.Sources) == 0 || len(rule.Sources) > maxRuleSources {
		return errors.New("source count is invalid")
	}
	if len(rule.Destinations) == 0 || len(rule.Destinations) > maxRuleDestinations {
		return errors.New("destination count is invalid")
	}
	for _, source := range rule.Sources {
		if err := validateSelector(source, true); err != nil {
			return fmt.Errorf("source: %w", err)
		}
	}
	for _, destination := range rule.Destinations {
		if err := validateSelector(destination.Selector, false); err != nil {
			return fmt.Errorf("destination: %w", err)
		}
		if destination.PortFrom > destination.PortTo {
			return errors.New("destination port range is reversed")
		}
	}

	return nil
}

func validateSelector(selector Selector, allowCapability bool) error {
	switch selector.Kind {
	case SelectorAny:
		if selector.Prefix.IsValid() || selector.RangeStart.IsValid() ||
			selector.RangeEnd.IsValid() || selector.Capability != "" {
			return errors.New("any selector contains extra values")
		}
	case SelectorPrefix:
		if !validPrefix(selector.Prefix) || selector.RangeStart.IsValid() ||
			selector.RangeEnd.IsValid() || selector.Capability != "" {
			return errors.New("prefix selector is malformed")
		}
	case SelectorRange:
		if selector.Prefix.IsValid() || selector.Capability != "" ||
			!selector.RangeStart.IsValid() || !selector.RangeEnd.IsValid() ||
			selector.RangeStart.BitLen() != selector.RangeEnd.BitLen() ||
			selector.RangeStart.Compare(selector.RangeEnd) > 0 {
			return errors.New("range selector is malformed")
		}
	case SelectorCapability:
		if !allowCapability || selector.Prefix.IsValid() || selector.RangeStart.IsValid() ||
			selector.RangeEnd.IsValid() || selector.Capability == "" ||
			len(selector.Capability) > maxCapabilityBytes ||
			strings.TrimSpace(selector.Capability) != selector.Capability ||
			containsSpaceOrControl(selector.Capability) {
			return errors.New("capability selector is malformed")
		}
	default:
		return errors.New("selector kind is unsupported")
	}

	return nil
}

func validateRelayRegion(region RelayRegion) error {
	if err := validateText("relay code", region.Code, maxNameRunes); err != nil {
		return err
	}
	if err := validateText("relay name", region.Name, maxNameRunes); err != nil {
		return err
	}
	if len(region.Nodes) == 0 || len(region.Nodes) > maxRelayNodes {
		return errors.New("relay node count is invalid")
	}
	for _, node := range region.Nodes {
		if err := validateText("relay node name", node.Name, maxNameRunes); err != nil {
			return err
		}
		if !validHostname(node.HostName, false) {
			return errors.New("relay hostname is invalid")
		}
		if node.CertName != "" && !validRelayCertName(node.CertName) {
			return errors.New("relay certificate name is invalid")
		}
		if err := validateText("relay hostname", node.HostName, maxNameRunes); err != nil {
			return err
		}
		if node.STUNPort < -1 || node.STUNPort > 65535 ||
			node.RelayPort < 0 || node.RelayPort > 65535 || node.UDPPort < 0 || node.UDPPort > 65535 {
			return errors.New("relay port is invalid")
		}
		for index, rawAddress := range []string{node.IPv4, node.IPv6} {
			if rawAddress == "" || rawAddress == "none" {
				continue
			}
			address, err := netip.ParseAddr(rawAddress)
			wrongFamily := (index == 0 && !address.Is4()) || (index == 1 && !address.Is6())
			if err != nil || wrongFamily || address.Is4In6() || address.Zone() != "" ||
				address != address.Unmap() || !address.IsGlobalUnicast() ||
				address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() ||
				address.IsLinkLocalUnicast() {
				return errors.New("relay address is invalid")
			}
		}
	}

	return nil
}

func validTypedKey(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	digest, err := hex.DecodeString(value[len(prefix):])

	return err == nil && len(digest) == 32 &&
		prefix+hex.EncodeToString(digest) == value && !allZero(digest)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}

	return true
}

func validPrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix == prefix.Masked() &&
		!prefix.Addr().IsMulticast() && !prefix.Addr().IsLoopback()
}

func validRelayCertName(value string) bool {
	const fingerprintPrefix = "sha256-raw:"
	if strings.HasPrefix(value, fingerprintPrefix) {
		digest, err := hex.DecodeString(strings.TrimPrefix(value, fingerprintPrefix))

		return err == nil && len(digest) == 32 && !allZero(digest) &&
			fingerprintPrefix+hex.EncodeToString(digest) == value
	}

	return validHostname(value, false)
}

func validHostname(value string, allowTrailingDot bool) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.IsValid() && !address.IsUnspecified()
	}
	if allowTrailingDot {
		value = strings.TrimSuffix(value, ".")
	}
	if value == "" || len(value) > maxNameRunes {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}

	return true
}

func containsSpaceOrControl(value string) bool {
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return true
		}
	}

	return false
}

func containsPrefix(prefixes []netip.Prefix, target netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == target {
			return true
		}
	}

	return false
}

func addDirectAddresses(seen map[netip.Addr]uint64, node Node) error {
	for _, prefix := range node.Addresses {
		address := prefix.Addr().Unmap()
		if prior, exists := seen[address]; exists {
			return fmt.Errorf("%w: direct address %s is shared by nodes %d and %d", ErrInvalid, address, prior, node.ID)
		}
		seen[address] = node.ID
	}

	return nil
}

func validateText(name, value string, maxRunes int) error {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		utf8.RuneCountInString(value) > maxRunes {
		return fmt.Errorf("%s is missing, malformed, or too long", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}

	return nil
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	cloned := snapshot
	cloned.Self = cloneNode(snapshot.Self)
	cloned.Peers = make([]Node, len(snapshot.Peers))
	for index, peer := range snapshot.Peers {
		cloned.Peers[index] = cloneNode(peer)
	}
	cloned.Policy = make([]Rule, len(snapshot.Policy))
	for index, rule := range snapshot.Policy {
		cloned.Policy[index] = Rule{
			Sources:      append([]Selector(nil), rule.Sources...),
			Destinations: append([]Destination(nil), rule.Destinations...),
			Protocols:    append([]uint8(nil), rule.Protocols...),
		}
	}
	cloned.Relays = make(map[int]RelayRegion, len(snapshot.Relays))
	for id, region := range snapshot.Relays {
		region.Nodes = append([]RelayNode(nil), region.Nodes...)
		cloned.Relays[id] = region
	}
	cloned.DNS = cloneDNSConfig(snapshot.DNS)
	if snapshot.Interchange != nil {
		interchange := *snapshot.Interchange
		interchange.Ticket = append([]byte(nil), interchange.Ticket...)
		interchange.TicketZones = append([]byte(nil), interchange.TicketZones...)
		interchange.FallbackTicket = append([]byte(nil), interchange.FallbackTicket...)
		cloned.Interchange = &interchange
	}
	cloned.Routes = cloneRoutes(snapshot.Routes)
	cloned.Served = cloneServed(snapshot.Served)
	cloned.ServedExits = cloneServedExits(snapshot.ServedExits)
	cloned.Exits = cloneExits(snapshot.Exits)
	if snapshot.ExitRoute != nil {
		route := *snapshot.ExitRoute
		cloned.ExitRoute = &route
	}

	return cloned
}

func cloneDNSConfig(config *DNSConfig) *DNSConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	cloned.Resolvers = append([]DNSResolver(nil), config.Resolvers...)
	cloned.FallbackResolvers = append([]DNSResolver(nil), config.FallbackResolvers...)
	cloned.Routes = make([]DNSRoute, len(config.Routes))
	for index, route := range config.Routes {
		cloned.Routes[index] = DNSRoute{
			Suffix:      route.Suffix,
			Resolvers:   append([]DNSResolver(nil), route.Resolvers...),
			Unavailable: route.Unavailable,
			FailOpen:    route.FailOpen,
		}
	}
	cloned.SearchDomains = append([]string(nil), config.SearchDomains...)
	cloned.Records = append([]DNSRecord(nil), config.Records...)

	return &cloned
}

func cloneNode(node Node) Node {
	node.Alias = cloneAlias(node.Alias)
	node.Addresses = append([]netip.Prefix(nil), node.Addresses...)
	node.AllowedIPs = append([]netip.Prefix(nil), node.AllowedIPs...)
	node.Endpoints = append([]netip.AddrPort(nil), node.Endpoints...)

	return node
}
