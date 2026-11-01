// Package flowcount counts what the packet filter allows and denies, per
// window, for connection logs (flowlog-v1 §5–6). The filter hands it one
// Observation per packet with what it decided; flowcount never parses a
// packet and never keeps packet bytes.
package flowcount

import (
	"net/netip"

	"meshtransit.net/client/internal/packetmeta"
)

// Class is what kind of traffic a packet belongs to (flowlog-v1 §6).
type Class uint8

const (
	ClassMesh Class = iota + 1
	ClassShare
	ClassSite
	ClassExit
)

// Direction is the flow's direction relative to this node.
type Direction uint8

const (
	// DirectionInbound is a flow another node opened to this one.
	DirectionInbound Direction = iota + 1
	// DirectionOutbound is a flow this node opened.
	DirectionOutbound
	// DirectionForwarded is a flow a router or exit node passes on.
	DirectionForwarded
)

// DenyReason is why the filter dropped a packet. DenyNone means it allowed
// it; DenyNoise means it dropped it but the drop is not worth a record.
type DenyReason uint8

const (
	DenyNone DenyReason = iota
	DenyNotInMap
	DenyPortNotAllowed
	DenyShareService
	DenyShareExpired
	DenyRouteNotInstalled
	DenyPeerUnusable
	DenyNoise
)

// ID is a 16-byte identifier from the node's map: a Device, Site, exit pool,
// trust contract or cluster. The zero ID means unknown.
type ID [16]byte

// Observation is one packet as the filter decided it, with Header.Source the
// packet's sender. Header holds this node's own mesh address and the other
// end's address as this node's map gives it: for a share, the alias address
// the map shows, never the other Workspace's real one.
type Observation struct {
	Header    packetmeta.Header
	Class     Class
	Direction Direction
	// Reply is true when the packet goes from the flow's destination back
	// to its source; its bytes count as inbound of the flow.
	Reply bool
	Deny  DenyReason
	// Peer is the other end's Device, when the map names it (not for a
	// share's provider seen from the consumer: Scope names the contract).
	Peer ID
	// Scope is the trust contract (share), Site, or exit pool of the flow.
	Scope ID
}

// isPrivate reports a mesh or private address: one whose IP may leave the
// node in a record. These are the mesh's ranges (100.64.0.0/10, unique local
// IPv6) and the private ranges a Site uses (10/8, 172.16/12, 192.168/16).
// Every other address is the Internet's and never does.
func isPrivate(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is4() {
		b := address.As4()
		return b[0] == 10 || b[0] == 172 && b[1]&0xf0 == 16 || b[0] == 192 && b[1] == 168 ||
			b[0] == 100 && b[1]&0xc0 == 64
	}
	return address.Is6() && address.As16()[0]&0xfe == 0xfc
}

// isNoise reports traffic no record is made of: multicast (mDNS, LLMNR,
// SSDP, router solicitations), broadcast and reserved IPv4, link-local,
// unspecified and loopback addresses.
func isNoise(header packetmeta.Header) bool {
	return noiseAddress(header.Source) || noiseAddress(header.Destination)
}

func noiseAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is4() {
		b := address.As4()
		return b[0] == 0 || b[0] == 127 || b[0] >= 224 || b[0] == 169 && b[1] == 254
	}
	if !address.Is6() {
		return true
	}
	b := address.As16()
	return address.IsUnspecified() || address.IsLoopback() || b[0] == 0xff || b[0] == 0xfe && b[1]&0xc0 == 0x80
}
