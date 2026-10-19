package dataplane

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
)

// prefixIndex finds the most specific of a bounded set of prefixes that
// contains an address: one map lookup per prefix length in use, at most 33
// for IPv4 and 129 for IPv6, without allocating.
type prefixIndex[T any] struct {
	values map[netip.Prefix]T
	// lengths are the prefix lengths in use per family, longest first.
	lengths4, lengths6 []int
}

func newPrefixIndex[T any](capacity int) *prefixIndex[T] {
	return &prefixIndex[T]{values: make(map[netip.Prefix]T, capacity)}
}

// add indexes a canonical prefix, keeping the first value of a prefix added
// twice; it reports whether the prefix was new.
func (p *prefixIndex[T]) add(prefix netip.Prefix, value T) bool {
	if _, listed := p.values[prefix]; listed {
		return false
	}
	p.values[prefix] = value
	lengths := &p.lengths6
	if prefix.Addr().Is4() {
		lengths = &p.lengths4
	}
	if !slices.Contains(*lengths, prefix.Bits()) {
		*lengths = append(*lengths, prefix.Bits())
		slices.SortFunc(*lengths, func(first, second int) int { return cmp.Compare(second, first) })
	}
	return true
}

func (p *prefixIndex[T]) lookup(address netip.Addr) (netip.Prefix, T, bool) {
	var zero T
	if p == nil || !address.IsValid() {
		return netip.Prefix{}, zero, false
	}
	address = address.Unmap()
	lengths := p.lengths6
	if address.Is4() {
		lengths = p.lengths4
	}
	for _, bits := range lengths {
		prefix := netip.PrefixFrom(address, bits).Masked()
		if value, found := p.values[prefix]; found {
			return prefix, value, true
		}
	}
	return netip.Prefix{}, zero, false
}

// removeContaining drops every indexed prefix that contains address, without
// allocating; a removed length stays listed, which only costs a lookup.
func (p *prefixIndex[T]) removeContaining(address netip.Addr) {
	if p == nil || !address.IsValid() {
		return
	}
	address = address.Unmap()
	lengths := p.lengths6
	if address.Is4() {
		lengths = p.lengths4
	}
	for _, bits := range lengths {
		delete(p.values, netip.PrefixFrom(address, bits).Masked())
	}
}

func (p *prefixIndex[T]) len() int {
	if p == nil {
		return 0
	}
	return len(p.values)
}

// sorted returns the indexed prefixes in address order.
func (p *prefixIndex[T]) sorted() []netip.Prefix {
	if p == nil {
		return nil
	}
	return slices.SortedFunc(maps.Keys(p.values), comparePrefixes)
}

func comparePrefixes(first, second netip.Prefix) int {
	if order := first.Addr().Compare(second.Addr()); order != 0 {
		return order
	}
	return cmp.Compare(first.Bits(), second.Bits())
}
