// Package relay owns the protocol-independent encrypted relay directory.
package relay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaximumRegions bounds one complete relay directory.
	MaximumRegions = 128
	// MaximumNodesPerRegion bounds failover candidates in one region.
	MaximumNodesPerRegion = 16
	maximumRegionID       = 1<<16 - 1
	maximumCodeBytes      = 32
	maximumNodeNameBytes  = 64
	maximumDisplayRunes   = 128
	maximumHostnameBytes  = 253
	certificatePinPrefix  = "sha256-raw:"
	redactedValue         = "[relay directory]"
)

var (
	// ErrInvalidDirectory reports an incomplete, ambiguous, or oversized directory.
	ErrInvalidDirectory = errors.New("relay: invalid directory")
	// ErrInvalidRegion reports an invalid relay region.
	ErrInvalidRegion = errors.New("relay: invalid region")
	// ErrInvalidNode reports an invalid relay node.
	ErrInvalidNode = errors.New("relay: invalid node")
)

// NodeParams contains one operator-authorized relay endpoint.
type NodeParams struct {
	Name       string
	HostName   string
	CertName   string
	IPv4       string
	IPv6       string
	STUNPort   int
	RelayPort  int
	IsSTUNOnly bool
}

// Node is an immutable relay endpoint. Empty address fields defer address
// resolution to the authenticated hostname; "none" disables one address family.
type Node struct {
	name       string
	hostName   string
	certName   string
	ipv4       string
	ipv6       string
	stunPort   int
	relayPort  int
	isSTUNOnly bool
}

// NewNode validates and copies one relay endpoint.
func NewNode(params NodeParams) (Node, error) {
	if !validToken(params.Name, maximumNodeNameBytes) ||
		!validHostname(params.HostName) ||
		(params.CertName != "" && !validCertificateName(params.CertName)) ||
		!validAddress(params.IPv4, true) || !validAddress(params.IPv6, false) ||
		params.STUNPort < -1 || params.STUNPort > 65535 ||
		params.RelayPort < 0 || params.RelayPort > 65535 {
		return Node{}, ErrInvalidNode
	}
	return Node{
		name:       params.Name,
		hostName:   params.HostName,
		certName:   params.CertName,
		ipv4:       params.IPv4,
		ipv6:       params.IPv6,
		stunPort:   params.STUNPort,
		relayPort:  params.RelayPort,
		isSTUNOnly: params.IsSTUNOnly,
	}, nil
}

// Name returns the stable node name within the directory.
func (node Node) Name() string { return node.name }

// HostName returns the canonical TLS and HTTP authority.
func (node Node) HostName() string { return node.hostName }

// CertName returns an optional alternate certificate name or exact pin.
func (node Node) CertName() string { return node.certName }

// IPv4 returns a literal address, "none", or an empty resolver directive.
func (node Node) IPv4() string { return node.ipv4 }

// IPv6 returns a literal address, "none", or an empty resolver directive.
func (node Node) IPv6() string { return node.ipv6 }

// STUNPort returns -1 for disabled, zero for the protocol default, or an explicit port.
func (node Node) STUNPort() int { return node.stunPort }

// RelayPort returns zero for the protocol default or an explicit port.
func (node Node) RelayPort() int { return node.relayPort }

// IsSTUNOnly reports whether the node is forbidden from carrying peer packets.
func (node Node) IsSTUNOnly() bool { return node.isSTUNOnly }

// IsValid reports whether the node is a complete canonical endpoint.
func (node Node) IsValid() bool {
	_, err := NewNode(node.params())
	return err == nil
}

// String redacts endpoint topology from ordinary formatting.
func (Node) String() string { return redactedValue }

// GoString redacts endpoint topology from Go-syntax formatting.
func (Node) GoString() string { return redactedValue }

// LogValue redacts endpoint topology from structured logs.
func (Node) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental serialization outside an explicit adapter.
func (Node) MarshalJSON() ([]byte, error) { return nil, ErrInvalidNode }

func (node Node) params() NodeParams {
	return NodeParams{
		Name:       node.name,
		HostName:   node.hostName,
		CertName:   node.certName,
		IPv4:       node.ipv4,
		IPv6:       node.ipv6,
		STUNPort:   node.stunPort,
		RelayPort:  node.relayPort,
		IsSTUNOnly: node.isSTUNOnly,
	}
}

// RegionParams contains one stable relay region and its ordered node set.
type RegionParams struct {
	ID    int
	Code  string
	Name  string
	Nodes []Node
}

// Region is an immutable ordered failover group.
type Region struct {
	id    int
	code  string
	name  string
	nodes []Node
}

// NewRegion validates, copies, and orders one region by node name.
func NewRegion(params RegionParams) (Region, error) {
	if params.ID <= 0 || params.ID > maximumRegionID ||
		!validToken(params.Code, maximumCodeBytes) || !validDisplayName(params.Name) ||
		len(params.Nodes) == 0 || len(params.Nodes) > MaximumNodesPerRegion {
		return Region{}, ErrInvalidRegion
	}
	nodes := slices.Clone(params.Nodes)
	slices.SortFunc(nodes, func(left, right Node) int {
		return strings.Compare(left.name, right.name)
	})
	names := make(map[string]struct{}, len(nodes))
	hosts := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if !node.IsValid() {
			return Region{}, ErrInvalidRegion
		}
		if _, duplicate := names[node.name]; duplicate {
			return Region{}, ErrInvalidRegion
		}
		if _, duplicate := hosts[node.hostName]; duplicate {
			return Region{}, ErrInvalidRegion
		}
		names[node.name] = struct{}{}
		hosts[node.hostName] = struct{}{}
	}
	return Region{id: params.ID, code: params.Code, name: params.Name, nodes: nodes}, nil
}

// ID returns the positive region identifier carried by the compatibility wire.
func (region Region) ID() int { return region.id }

// Code returns the stable compact region code.
func (region Region) Code() string { return region.code }

// Name returns the operator-facing region display name.
func (region Region) Name() string { return region.name }

// Nodes returns a caller-owned copy in deterministic failover order.
func (region Region) Nodes() []Node { return slices.Clone(region.nodes) }

// IsValid reports whether the region contains canonical unique nodes.
func (region Region) IsValid() bool {
	_, err := NewRegion(region.params())
	return err == nil
}

// String redacts region topology from ordinary formatting.
func (Region) String() string { return redactedValue }

// GoString redacts region topology from Go-syntax formatting.
func (Region) GoString() string { return redactedValue }

// LogValue redacts region topology from structured logs.
func (Region) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental serialization outside an explicit adapter.
func (Region) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRegion }

func (region Region) params() RegionParams {
	return RegionParams{ID: region.id, Code: region.code, Name: region.name, Nodes: slices.Clone(region.nodes)}
}

// DirectoryParams contains one complete versioned relay topology.
type DirectoryParams struct {
	Revision uint64
	Regions  []Region
}

// Directory is an immutable complete relay topology. It carries no peer,
// Network, route, or packet-policy authority.
type Directory struct {
	revision    uint64
	regions     []Region
	fingerprint [sha256.Size]byte
}

// NewDirectory validates, defensively copies, and canonically orders a complete directory.
func NewDirectory(params DirectoryParams) (Directory, error) {
	if params.Revision == 0 || len(params.Regions) == 0 || len(params.Regions) > MaximumRegions {
		return Directory{}, ErrInvalidDirectory
	}
	regions := slices.Clone(params.Regions)
	slices.SortFunc(regions, func(left, right Region) int { return left.id - right.id })
	regionCodes := make(map[string]struct{}, len(regions))
	nodeNames := make(map[string]struct{})
	nodeHosts := make(map[string]struct{})
	lastID := 0
	for _, region := range regions {
		if !region.IsValid() || region.id == lastID {
			return Directory{}, ErrInvalidDirectory
		}
		lastID = region.id
		if _, duplicate := regionCodes[region.code]; duplicate {
			return Directory{}, ErrInvalidDirectory
		}
		regionCodes[region.code] = struct{}{}
		for _, node := range region.nodes {
			if _, duplicate := nodeNames[node.name]; duplicate {
				return Directory{}, ErrInvalidDirectory
			}
			if _, duplicate := nodeHosts[node.hostName]; duplicate {
				return Directory{}, ErrInvalidDirectory
			}
			nodeNames[node.name] = struct{}{}
			nodeHosts[node.hostName] = struct{}{}
		}
	}
	return Directory{
		revision:    params.Revision,
		regions:     regions,
		fingerprint: fingerprint(regions),
	}, nil
}

// Revision returns the operator-controlled monotonic directory revision.
func (directory Directory) Revision() uint64 { return directory.revision }

// Regions returns a deep caller-owned copy ordered by region ID.
func (directory Directory) Regions() []Region { return cloneRegions(directory.regions) }

// Region returns a caller-owned region with the requested ID.
func (directory Directory) Region(id int) (Region, bool) {
	index, found := slices.BinarySearchFunc(directory.regions, id, func(region Region, target int) int {
		return region.id - target
	})
	if !found {
		return Region{}, false
	}
	return cloneRegion(directory.regions[index]), true
}

// Fingerprint identifies canonical topology independently from its revision.
func (directory Directory) Fingerprint() [sha256.Size]byte { return directory.fingerprint }

// IsValid reports whether the directory is complete and internally consistent.
func (directory Directory) IsValid() bool {
	validated, err := NewDirectory(DirectoryParams{
		Revision: directory.revision,
		Regions:  directory.regions,
	})
	return err == nil && validated.fingerprint == directory.fingerprint
}

// String redacts the complete topology from ordinary formatting.
func (Directory) String() string { return redactedValue }

// GoString redacts the complete topology from Go-syntax formatting.
func (Directory) GoString() string { return redactedValue }

// LogValue redacts the complete topology from structured logs.
func (Directory) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental serialization outside an explicit adapter.
func (Directory) MarshalJSON() ([]byte, error) { return nil, ErrInvalidDirectory }

func cloneRegions(regions []Region) []Region {
	cloned := make([]Region, len(regions))
	for index, region := range regions {
		cloned[index] = cloneRegion(region)
	}
	return cloned
}

func cloneRegion(region Region) Region {
	region.nodes = slices.Clone(region.nodes)
	return region
}

func fingerprint(regions []Region) [sha256.Size]byte {
	material := make([]byte, 0, len(regions)*128)
	material = appendUnsigned(material, uint64(len(regions)))
	for _, region := range regions {
		material = appendInteger(material, int64(region.id))
		material = appendString(material, region.code)
		material = appendString(material, region.name)
		material = appendUnsigned(material, uint64(len(region.nodes)))
		for _, node := range region.nodes {
			material = appendString(material, node.name)
			material = appendString(material, node.hostName)
			material = appendString(material, node.certName)
			material = appendString(material, node.ipv4)
			material = appendString(material, node.ipv6)
			material = appendInteger(material, int64(node.stunPort+1))
			material = appendInteger(material, int64(node.relayPort))
			material = append(material, byte(0))
			if node.isSTUNOnly {
				material[len(material)-1] = 1
			}
		}
	}
	return sha256.Sum256(material)
}

func appendUnsigned(destination []byte, value uint64) []byte {
	return binary.AppendUvarint(destination, value)
}

func appendInteger(destination []byte, value int64) []byte {
	return binary.AppendVarint(destination, value)
}

func appendString(destination []byte, value string) []byte {
	destination = appendUnsigned(destination, uint64(len(value)))
	return append(destination, value...)
}

func validToken(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validDisplayName(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		utf8.RuneCountInString(value) > maximumDisplayRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validHostname(value string) bool {
	if value == "" || len(value) > maximumHostnameBytes || value != strings.ToLower(value) {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !validToken(label, 63) {
			return false
		}
	}
	return true
}

func validCertificateName(value string) bool {
	if strings.HasPrefix(value, certificatePinPrefix) {
		digest, err := hex.DecodeString(strings.TrimPrefix(value, certificatePinPrefix))
		return err == nil && len(digest) == sha256.Size &&
			certificatePinPrefix+hex.EncodeToString(digest) == value && !allZero(digest)
	}
	return validHostname(value)
}

func validAddress(value string, isIPv4 bool) bool {
	if value == "" || value == "none" {
		return true
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Is4In6() || address.Zone() != "" || address != address.Unmap() ||
		address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || !address.IsGlobalUnicast() {
		return false
	}
	return (isIPv4 && address.Is4()) || (!isIPv4 && address.Is6())
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
