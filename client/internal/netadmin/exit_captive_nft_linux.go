//go:build linux

package netadmin

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The kill switch's captive portal holes (exit node design §17.5, §17.6):
// sets keyed by interface, its own address and a TCP port (and the portal's
// address for its own port), whose elements the kernel drops when the
// window ends, also when the helper is gone. The sets and the rules that
// look them up are always there; only a window fills them.

// captiveSetTimeout is the sets' own timeout, a backstop: every element
// carries the window's time left, never more than captive.MaximumWindow.
const captiveSetTimeout = 5 * time.Minute

// maximumCaptiveAddresses bounds the addresses of the window's interface
// opened per family.
const maximumCaptiveAddresses = 8

// captivePorts are what a window lets out to any destination: HTTP and
// HTTPS, which a portal intercepts and serves its sign-in page on.
var captivePorts = []uint16{80, 443}

// captiveOpening is where a window opens in one family: the interface of the
// main table's default route, and its addresses.
type captiveOpening struct {
	name      string
	addresses []netip.Addr
}

// captiveHoles is what the kill switch lets out during a window.
type captiveHoles struct {
	openings  []captiveOpening
	portals   [2]netip.AddrPort
	remaining time.Duration
}

// captiveSets are the kill switch's four hole sets.
type captiveSets struct {
	open4, open6, portal4, portal6 *nftables.Set
}

func newCaptiveSets(table *nftables.Table) captiveSets {
	set := func(name string, types ...nftables.SetDatatype) *nftables.Set {
		return &nftables.Set{
			Table: table, Name: name, KeyType: nftables.MustConcatSetType(types...), Concatenation: true,
			HasTimeout: true, Timeout: captiveSetTimeout,
		}
	}
	return captiveSets{
		open4: set("captive4", nftables.TypeIFName, nftables.TypeIPAddr, nftables.TypeInetService),
		open6: set("captive6", nftables.TypeIFName, nftables.TypeIP6Addr, nftables.TypeInetService),
		portal4: set("portal4", nftables.TypeIFName, nftables.TypeIPAddr, nftables.TypeIPAddr,
			nftables.TypeInetService),
		portal6: set("portal6", nftables.TypeIFName, nftables.TypeIP6Addr, nftables.TypeIP6Addr,
			nftables.TypeInetService),
	}
}

// add adds the sets with the holes' elements, if any.
func (sets captiveSets) add(conn *nftables.Conn, holes *captiveHoles) error {
	elements := captiveElements(holes)
	for _, set := range []*nftables.Set{sets.open4, sets.open6, sets.portal4, sets.portal6} {
		if err := conn.AddSet(set, elements[set.Name]); err != nil {
			return fmt.Errorf("adding kill switch set %s: %w", set.Name, err)
		}
	}
	return nil
}

// captiveElements are the sets' elements for holes, by set name, each with
// the window's time left.
func captiveElements(holes *captiveHoles) map[string][]nftables.SetElement {
	elements := map[string][]nftables.SetElement{}
	if holes == nil || holes.remaining <= 0 {
		return elements
	}
	timeout := max(holes.remaining, time.Millisecond)
	for _, opening := range holes.openings {
		for _, address := range opening.addresses {
			ipv4 := address.Is4()
			open, portal, slot := "captive6", "portal6", 1
			if ipv4 {
				open, portal, slot = "captive4", "portal4", 0
			}
			for _, port := range captivePorts {
				elements[open] = append(elements[open], nftables.SetElement{
					Key: captiveKey(opening.name, address, netip.Addr{}, port), Timeout: timeout,
				})
			}
			if target := holes.portals[slot]; target.IsValid() {
				elements[portal] = append(elements[portal], nftables.SetElement{
					Key: captiveKey(opening.name, address, target.Addr(), target.Port()), Timeout: timeout,
				})
			}
		}
	}
	return elements
}

// captiveKey is a set key as the kernel lays it out: each field padded to
// four bytes, the interface name to IFNAMSIZ, the port in network order.
func captiveKey(name string, source, destination netip.Addr, port uint16) []byte {
	key := make([]byte, unix.IFNAMSIZ, unix.IFNAMSIZ+40)
	copy(key, name)
	key = append(key, source.AsSlice()...)
	if destination.IsValid() {
		key = append(key, destination.AsSlice()...)
	}
	return append(binary.BigEndian.AppendUint16(key, port), 0, 0)
}

// captiveKeys names the elements of holes as elementKeys does, by set.
func captiveKeys(holes *captiveHoles) map[string][]string {
	keys := map[string][]string{}
	for name, elements := range captiveElements(holes) {
		keys[name] = elementKeys(elements)
	}
	return keys
}

// captiveFields are where a family's packet fields lie and how long they are.
type captiveFields struct {
	protocol            byte
	source, destination uint32
	length              uint32
}

var (
	captiveFields4 = captiveFields{unix.NFPROTO_IPV4, 12, 16, 4}
	captiveFields6 = captiveFields{unix.NFPROTO_IPV6, 8, 24, 16}
)

// captiveOutputRules accept the host's own TCP packets out by the window's
// interface from its own address to the ports opened, and to the portal.
func captiveOutputRules(sets captiveSets) [][]expr.Any {
	return [][]expr.Any{
		captiveLookup(captiveFields4, expr.MetaKeyOIFNAME, false, false, sets.open4, verdict(expr.VerdictAccept)),
		captiveLookup(captiveFields4, expr.MetaKeyOIFNAME, false, true, sets.portal4, verdict(expr.VerdictAccept)),
		captiveLookup(captiveFields6, expr.MetaKeyOIFNAME, false, false, sets.open6, verdict(expr.VerdictAccept)),
		captiveLookup(captiveFields6, expr.MetaKeyOIFNAME, false, true, sets.portal6, verdict(expr.VerdictAccept)),
	}
}

// captiveReplyRules mark the replies the window's connections receive, so
// the kernel's reverse path check looks their source up in the main table,
// as for connections opened from outside: the mark goes on the packet only,
// never on the connection, which the kill switch would then let out after
// the window.
func captiveReplyRules(sets captiveSets) [][]expr.Any {
	mark := setMetaMark(exitInboundMark)
	return [][]expr.Any{
		captiveLookup(captiveFields4, expr.MetaKeyIIFNAME, true, false, sets.open4, mark),
		captiveLookup(captiveFields4, expr.MetaKeyIIFNAME, true, true, sets.portal4, mark),
		captiveLookup(captiveFields6, expr.MetaKeyIIFNAME, true, false, sets.open6, mark),
		captiveLookup(captiveFields6, expr.MetaKeyIIFNAME, true, true, sets.portal6, mark),
	}
}

// captiveLookup matches a TCP packet of fields' family whose interface, host
// address and remote port (and, toPortal, remote address) are in set: a
// packet the host sends, or with reply, one it receives.
func captiveLookup(
	fields captiveFields, interfaceKey expr.MetaKey, reply, toPortal bool, set *nftables.Set, then []expr.Any,
) []expr.Any {
	local, remote := fields.source, fields.destination
	remotePort := uint32(2) // destination port
	if reply {
		local, remote, remotePort = fields.destination, fields.source, 0
	}
	// Concatenated keys sit in the 32-bit registers from NFT_REG32_00 on.
	const firstRegister = 8
	register := uint32(firstRegister)
	rule := join(family(fields.protocol), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Meta{Key: interfaceKey, Register: register},
	})
	register += unix.IFNAMSIZ / 4
	rule = append(rule, &expr.Payload{
		DestRegister: register, Base: expr.PayloadBaseNetworkHeader, Offset: local, Len: fields.length,
	})
	register += fields.length / 4
	if toPortal {
		rule = append(rule, &expr.Payload{
			DestRegister: register, Base: expr.PayloadBaseNetworkHeader, Offset: remote, Len: fields.length,
		})
		register += fields.length / 4
	}
	rule = append(rule,
		&expr.Payload{DestRegister: register, Base: expr.PayloadBaseTransportHeader, Offset: remotePort, Len: 2},
		&expr.Lookup{SourceRegister: firstRegister, SetName: set.Name, SetID: set.ID},
	)
	return append(rule, then...)
}

// captiveRouteRules send the host's own TCP to the ports a window opens,
// and to the portal, by the main table, in each family it opens: packets
// from the host only (iif lo), never forwarded ones.
func captiveRouteRules(priority int, holes *captiveHoles) []*netlink.Rule {
	if holes == nil {
		return nil
	}
	var rules []*netlink.Rule
	for slot, kind := range []int{unix.AF_INET, unix.AF_INET6} {
		if !slices.ContainsFunc(holes.openings, func(opening captiveOpening) bool {
			return len(opening.addresses) != 0 && opening.addresses[0].Is4() == (slot == 0)
		}) {
			continue
		}
		toPort := func(port uint16, to netip.Addr) *netlink.Rule {
			opened := netlink.NewRule()
			opened.Family, opened.Priority, opened.Table = kind, priority, unix.RT_TABLE_MAIN
			opened.IifName, opened.IPProto = "lo", unix.IPPROTO_TCP
			opened.Dport = netlink.NewRulePortRange(port, port)
			if to.IsValid() {
				opened.Dst = prefixIPNet(netip.PrefixFrom(to, to.BitLen()))
			}
			return opened
		}
		for _, port := range captivePorts {
			rules = append(rules, toPort(port, netip.Addr{}))
		}
		if portal := holes.portals[slot]; portal.IsValid() {
			rules = append(rules, toPort(portal.Port(), portal.Addr()))
		}
	}
	return rules
}
