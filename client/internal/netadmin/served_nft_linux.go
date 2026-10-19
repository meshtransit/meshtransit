//go:build linux

package netadmin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// servedRuleset is what the router table enforces (design §8.1, layer 2).
type servedRuleset struct {
	// Table is the helper's own inet table.
	Table string
	// Interface is the mesh TUN; Self its own (overlay) addresses.
	Interface string
	Self      []netip.Prefix
	// MTU of the TUN, for MSS clamping.
	MTU int
	// Served are the prefixes forwarded into; Masquerade those whose
	// sources are translated to the router's own address.
	Served     []netip.Prefix
	Masquerade []netip.Prefix
	// Guarded are interfaces whose IPv4 forwarding the helper turned on;
	// GuardIPv6 means it turned on IPv6 forwarding for the whole host. Their
	// forwarding is kept to traffic to and from the TUN.
	Guarded   []string
	GuardIPv6 bool
}

const (
	ipv4HeaderBytes = 20
	ipv6HeaderBytes = 40
	tcpHeaderBytes  = 20
	// tcpOptionMSS is the maximum segment size option (RFC 9293).
	tcpOptionMSS = 2
)

// replaceServedTable installs ruleset as one atomic transaction: the table
// is deleted, when present, and created again, so no packet ever sees a mix
// of old and new rules.
func replaceServedTable(ruleset servedRuleset) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("opening nftables: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: ruleset.Table}
	// Adding an existing table changes nothing, so the deletion below
	// always finds one.
	conn.AddTable(table)
	conn.DelTable(table)
	conn.AddTable(table)
	sets, err := addServedSets(conn, table, ruleset)
	if err != nil {
		return err
	}
	forward := conn.AddChain(&nftables.Chain{
		Name: "forward", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
	})
	input := conn.AddChain(&nftables.Chain{
		Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter,
	})
	postrouting := conn.AddChain(&nftables.Chain{
		Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
	})
	for _, exprs := range forwardRules(ruleset, sets) {
		conn.AddRule(&nftables.Rule{Table: table, Chain: forward, Exprs: exprs})
	}
	for _, exprs := range inputRules(ruleset, sets) {
		conn.AddRule(&nftables.Rule{Table: table, Chain: input, Exprs: exprs})
	}
	for _, exprs := range postroutingRules(ruleset, sets) {
		conn.AddRule(&nftables.Rule{Table: table, Chain: postrouting, Exprs: exprs})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("installing router rules: %w", err)
	}
	return nil
}

// deleteServedTable removes the table when it is installed; a kernel
// without nftables has none to remove.
func deleteServedTable(name string) error {
	present, err := servedTablePresent(name)
	if err != nil || !present {
		if nftablesUnavailable(err) {
			return nil
		}
		return err
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("opening nftables: %w", err)
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
	if err := conn.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("removing router rules: %w", err)
	}
	return nil
}

// nftablesUnavailable reports an error of a kernel without nf_tables.
func nftablesUnavailable(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPROTONOSUPPORT) || errors.Is(err, unix.EAFNOSUPPORT)
}

// servedTablePresent reports whether the table is installed, so a table
// another tool flushed is installed again.
func servedTablePresent(name string) (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("opening nftables: %w", err)
	}
	if _, err := conn.ListTableOfFamily(name, nftables.TableFamilyINet); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("listing router rules: %w", err)
	}
	return true, nil
}

type servedSets struct {
	served4, served6, masquerade4, masquerade6, self4, self6 *nftables.Set
}

func addServedSets(conn *nftables.Conn, table *nftables.Table, ruleset servedRuleset) (servedSets, error) {
	var sets servedSets
	for _, set := range []struct {
		target   **nftables.Set
		name     string
		prefixes []netip.Prefix
		ipv4     bool
	}{
		{&sets.served4, "served4", ruleset.Served, true},
		{&sets.served6, "served6", ruleset.Served, false},
		{&sets.masquerade4, "masquerade4", ruleset.Masquerade, true},
		{&sets.masquerade6, "masquerade6", ruleset.Masquerade, false},
		{&sets.self4, "self4", ruleset.Self, true},
		{&sets.self6, "self6", ruleset.Self, false},
	} {
		keyType := nftables.TypeIP6Addr
		if set.ipv4 {
			keyType = nftables.TypeIPAddr
		}
		created := &nftables.Set{Table: table, Name: set.name, KeyType: keyType, Interval: true}
		if err := conn.AddSet(created, intervalElements(set.prefixes, set.ipv4)); err != nil {
			return servedSets{}, fmt.Errorf("adding router set %s: %w", set.name, err)
		}
		*set.target = created
	}
	return sets, nil
}

// addressRange is the first and last address of one or more prefixes.
type addressRange struct{ first, last netip.Addr }

// intervalElements encodes the prefixes of one family as the ranges of an
// interval set, as nft does: adjacent and overlapping prefixes merged into
// one range, each range its first address and, as its end, the address
// after its last. A range reaching the top of the address space has no end
// element: the kernel takes it to the end.
func intervalElements(prefixes []netip.Prefix, ipv4 bool) []nftables.SetElement {
	var elements []nftables.SetElement
	for _, merged := range mergedRanges(prefixes, ipv4) {
		elements = append(elements, nftables.SetElement{Key: merged.first.AsSlice()})
		if after := merged.last.Next(); after.IsValid() {
			elements = append(elements, nftables.SetElement{Key: after.AsSlice(), IntervalEnd: true})
		}
	}
	return elements
}

// mergedRanges returns the prefixes of one family as sorted ranges that
// neither overlap nor touch.
func mergedRanges(prefixes []netip.Prefix, ipv4 bool) []addressRange {
	var ranges []addressRange
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() == ipv4 {
			ranges = append(ranges, addressRange{first: prefix.Masked().Addr(), last: lastAddress(prefix)})
		}
	}
	slices.SortFunc(ranges, func(left, right addressRange) int { return left.first.Compare(right.first) })
	merged := ranges[:0]
	for _, next := range ranges {
		if count := len(merged); count > 0 {
			current := &merged[count-1]
			after := current.last.Next()
			if !after.IsValid() || next.first.Compare(after) <= 0 {
				if next.last.Compare(current.last) > 0 {
					current.last = next.last
				}
				continue
			}
		}
		merged = append(merged, next)
	}
	return merged
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= 0x80 >> (bit % 8)
	}
	address, _ := netip.AddrFromSlice(bytes)
	return address
}

func forwardRules(ruleset servedRuleset, sets servedSets) [][]expr.Any {
	established := ctState(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	rules := [][]expr.Any{
		// Segments through the TUN fit its MTU, either way.
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), clampMSS(unix.NFPROTO_IPV4, ruleset.MTU-ipv4HeaderBytes-tcpHeaderBytes)),
		join(interfaceIs(expr.MetaKeyOIFNAME, ruleset.Interface), clampMSS(unix.NFPROTO_IPV4, ruleset.MTU-ipv4HeaderBytes-tcpHeaderBytes)),
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), clampMSS(unix.NFPROTO_IPV6, ruleset.MTU-ipv6HeaderBytes-tcpHeaderBytes)),
		join(interfaceIs(expr.MetaKeyOIFNAME, ruleset.Interface), clampMSS(unix.NFPROTO_IPV6, ruleset.MTU-ipv6HeaderBytes-tcpHeaderBytes)),
		// From the mesh: replies, and new traffic only into served
		// prefixes; the router is no exit node.
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), established, verdict(expr.VerdictAccept)),
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), family(unix.NFPROTO_IPV4),
			addressIn(false, 16, 4, sets.served4), verdict(expr.VerdictAccept)),
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), family(unix.NFPROTO_IPV6),
			addressIn(false, 24, 16, sets.served6), verdict(expr.VerdictAccept)),
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), verdict(expr.VerdictDrop)),
		// Into the mesh: only replies. A Site cannot open connections into
		// the mesh.
		join(interfaceIs(expr.MetaKeyOIFNAME, ruleset.Interface), established, verdict(expr.VerdictAccept)),
		join(interfaceIs(expr.MetaKeyOIFNAME, ruleset.Interface), verdict(expr.VerdictDrop)),
	}
	// Forwarding the helper turned on serves the mesh only: the host does
	// not start routing between its other networks.
	for _, name := range ruleset.Guarded {
		rules = append(rules, join(interfaceIs(expr.MetaKeyIIFNAME, name), family(unix.NFPROTO_IPV4), verdict(expr.VerdictDrop)))
	}
	if ruleset.GuardIPv6 {
		rules = append(rules, join(family(unix.NFPROTO_IPV6), verdict(expr.VerdictDrop)))
	}
	return rules
}

// inputRules keep the mesh off the router's own non-overlay addresses: a
// consumer granted the router's LAN reaches its hosts, never the router's
// own services there (design §8.1).
func inputRules(ruleset servedRuleset, sets servedSets) [][]expr.Any {
	return [][]expr.Any{
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), family(unix.NFPROTO_IPV4),
			addressIn(true, 16, 4, sets.self4), verdict(expr.VerdictDrop)),
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), family(unix.NFPROTO_IPV6),
			addressIn(true, 24, 16, sets.self6), verdict(expr.VerdictDrop)),
	}
}

func postroutingRules(ruleset servedRuleset, sets servedSets) [][]expr.Any {
	return [][]expr.Any{
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), family(unix.NFPROTO_IPV4),
			addressIn(false, 16, 4, sets.masquerade4), []expr.Any{&expr.Masq{}}),
		join(interfaceIs(expr.MetaKeyIIFNAME, ruleset.Interface), family(unix.NFPROTO_IPV6),
			addressIn(false, 24, 16, sets.masquerade6), []expr.Any{&expr.Masq{}}),
	}
}

func join(parts ...[]expr.Any) []expr.Any {
	var joined []expr.Any
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

func interfaceIs(key expr.MetaKey, name string) []expr.Any {
	padded := make([]byte, unix.IFNAMSIZ)
	copy(padded, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: padded},
	}
}

func family(protocol byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
	}
}

// addressIn matches a destination address at offset in the network header
// that is (or, inverted, is not) in set.
func addressIn(invert bool, offset, length uint32, set *nftables.Set) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID, Invert: invert},
	}
}

func ctState(bits uint32) []expr.Any {
	mask := make([]byte, 4)
	binary.NativeEndian.PutUint32(mask, bits)
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
}

// clampMSS lowers the MSS option of a TCP SYN of one family to maximum; it
// never raises it.
func clampMSS(protocol byte, maximum int) []expr.Any {
	limit := make([]byte, 2)
	binary.BigEndian.PutUint16(limit, uint16(max(maximum, 0))) //nolint:gosec // G115: an MTU fits
	return join(family(protocol), []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x02}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0}},
		&expr.Exthdr{DestRegister: 1, Type: tcpOptionMSS, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
		&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: limit},
		&expr.Immediate{Register: 1, Data: limit},
		&expr.Exthdr{SourceRegister: 1, Type: tcpOptionMSS, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
	})
}

func verdict(kind expr.VerdictKind) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: kind}}
}
