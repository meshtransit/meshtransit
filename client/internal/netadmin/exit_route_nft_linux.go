//go:build linux

package netadmin

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// exitKillSwitch is what the helper's kill switch lets leave the host
// outside the mesh while it uses an exit node (exit node design §6.4).
type exitKillSwitch struct {
	// Table is the helper's own inet table for it.
	Table string
	// Interface is the mesh TUN; Inner the interfaces packets may always
	// leave by: the TUN, loopback, and local bridges without a physical
	// port.
	Interface string
	Inner     []string
	// UID is meshd's: its own sockets reach Core, relays and peers.
	UID uint32
	// LAN are the allowed attached private subnets and link-local
	// multicast; empty unless the LAN is allowed.
	LAN []netip.Prefix
}

// ICMPv6 types the host sends to keep its links working: router and
// neighbour solicitations and advertisements, and multicast listener
// reports.
var exitNeighbourTypes = []byte{133, 135, 136, 131, 143}

// replaceExitKillSwitch installs the kill switch as one atomic transaction,
// replacing the table when present.
func replaceExitKillSwitch(ruleset exitKillSwitch) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("opening nftables: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: ruleset.Table}
	conn.AddTable(table)
	conn.DelTable(table)
	conn.AddTable(table)
	lan4 := &nftables.Set{Table: table, Name: "lan4", KeyType: nftables.TypeIPAddr, Interval: true}
	lan6 := &nftables.Set{Table: table, Name: "lan6", KeyType: nftables.TypeIP6Addr, Interval: true}
	for _, set := range []struct {
		set  *nftables.Set
		ipv4 bool
	}{{lan4, true}, {lan6, false}} {
		if err := conn.AddSet(set.set, intervalElements(ruleset.LAN, set.ipv4)); err != nil {
			return fmt.Errorf("adding kill switch set %s: %w", set.set.Name, err)
		}
	}
	chains := []struct {
		name     string
		kind     nftables.ChainType
		hook     *nftables.ChainHook
		priority *nftables.ChainPriority
		rules    [][]expr.Any
	}{
		{
			"prerouting", nftables.ChainTypeFilter, nftables.ChainHookPrerouting, nftables.ChainPriorityMangle,
			exitMarkInboundRules(ruleset),
		},
		{
			"route", nftables.ChainTypeRoute, nftables.ChainHookOutput, nftables.ChainPriorityMangle,
			exitRerouteRules(),
		},
		{
			"output", nftables.ChainTypeFilter, nftables.ChainHookOutput, nftables.ChainPriorityFilter,
			exitOutputRules(ruleset, lan4, lan6),
		},
		{
			"forward", nftables.ChainTypeFilter, nftables.ChainHookForward, nftables.ChainPriorityFilter,
			exitForwardKillRules(ruleset, lan4, lan6),
		},
	}
	for _, definition := range chains {
		chain := conn.AddChain(&nftables.Chain{
			Name: definition.name, Table: table, Type: definition.kind, Hooknum: definition.hook,
			Priority: definition.priority,
		})
		for _, exprs := range definition.rules {
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("installing the exit kill switch: %w", err)
	}
	return nil
}

// exitMarkInboundRules mark each connection opened from outside the host,
// other than through the mesh or a local bridge, so its replies leave by
// the host's own routes (a VPS keeps its SSH): a packet in the original
// direction arriving there was sent by the remote end that opened it, also
// for connections opened before the exit node was used. Replies routed
// for a container (published ports) carry the mark into the routing
// decision.
func exitMarkInboundRules(ruleset exitKillSwitch) [][]expr.Any {
	rules := make([][]expr.Any, 0, len(ruleset.Inner)+2)
	rules = append(rules, join(ctMarked(exitInboundMark), setMetaMark(exitInboundMark)))
	for _, name := range ruleset.Inner {
		rules = append(rules, join(interfaceIs(expr.MetaKeyIIFNAME, name), verdict(expr.VerdictReturn)))
	}
	original := []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
	}
	return append(rules, join(original, setCtMark(exitInboundMark)))
}

// exitRerouteRules copy the inbound mark of a connection to the host's own
// packets of it, which the route chain looks up again (rule ExitPriority).
func exitRerouteRules() [][]expr.Any {
	return [][]expr.Any{join(ctMarked(exitInboundMark), setMetaMark(exitInboundMark))}
}

// exitOutputRules let the host's own packets leave outside the mesh only by
// the exceptions: inner interfaces, meshd, connections opened from outside,
// DHCP, neighbour discovery and the allowed LAN.
func exitOutputRules(ruleset exitKillSwitch, lan4, lan6 *nftables.Set) [][]expr.Any {
	rules := make([][]expr.Any, 0, len(ruleset.Inner)+16)
	for _, name := range ruleset.Inner {
		rules = append(rules, join(interfaceIs(expr.MetaKeyOIFNAME, name), verdict(expr.VerdictAccept)))
	}
	uid := make([]byte, 4)
	binary.NativeEndian.PutUint32(uid, ruleset.UID)
	rules = append(rules,
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: uid},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
		join(ctMarked(exitInboundMark), verdict(expr.VerdictAccept)),
		join(family(unix.NFPROTO_IPV4), udpPorts(68, 67), verdict(expr.VerdictAccept)),
		join(family(unix.NFPROTO_IPV6), udpPorts(546, 547), verdict(expr.VerdictAccept)),
	)
	for _, kind := range exitNeighbourTypes {
		rules = append(rules, join(family(unix.NFPROTO_IPV6), []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{kind}},
		}, verdict(expr.VerdictAccept)))
	}
	rules = append(rules, exitLANRules(lan4, lan6)...)
	return append(rules, join([]expr.Any{&expr.Counter{}}, verdict(expr.VerdictDrop)))
}

// exitForwardKillRules let forwarded packets (containers, VMs) leave outside
// the mesh only into inner interfaces, from the mesh (the host's own router
// or exit node roles, which their own rules check), as replies to
// connections opened from outside, or into the allowed LAN.
func exitForwardKillRules(ruleset exitKillSwitch, lan4, lan6 *nftables.Set) [][]expr.Any {
	rules := make([][]expr.Any, 0, len(ruleset.Inner)+6)
	for _, name := range ruleset.Inner {
		rules = append(rules, join(interfaceIs(expr.MetaKeyOIFNAME, name), verdict(expr.VerdictAccept)))
	}
	if ruleset.Interface != "" {
		rules = append(rules, join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), verdict(expr.VerdictAccept)))
	}
	rules = append(rules, join(ctMarked(exitInboundMark), verdict(expr.VerdictAccept)))
	rules = append(rules, exitLANRules(lan4, lan6)...)
	return append(rules, join([]expr.Any{&expr.Counter{}}, verdict(expr.VerdictDrop)))
}

func exitLANRules(lan4, lan6 *nftables.Set) [][]expr.Any {
	return [][]expr.Any{
		join(family(unix.NFPROTO_IPV4), addressIn(false, 16, 4, lan4), verdict(expr.VerdictAccept)),
		join(family(unix.NFPROTO_IPV6), addressIn(false, 24, 16, lan6), verdict(expr.VerdictAccept)),
	}
}

// udpPorts matches UDP from source to destination port.
func udpPorts(source, destination uint16) []expr.Any {
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[0:2], source)
	binary.BigEndian.PutUint16(ports[2:4], destination)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports},
	}
}

// ctMarked matches a connection whose mark has bit.
func ctMarked(bit uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: nativeUint32(bit), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
}

// setCtMark adds bit to the connection's mark, keeping the others.
func setCtMark(bit uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: nativeUint32(^bit), Xor: nativeUint32(bit)},
		&expr.Ct{Register: 1, Key: expr.CtKeyMARK, SourceRegister: true},
	}
}

// setMetaMark adds bit to the packet's mark, keeping the others.
func setMetaMark(bit uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: nativeUint32(^bit), Xor: nativeUint32(bit)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
	}
}

func nativeUint32(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.NativeEndian.PutUint32(encoded, value)
	return encoded
}
