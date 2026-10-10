//go:build !linux

package dataplane

import "net/netip"

// ipv6AddressStates is implemented on Linux only; elsewhere every address
// counts as stable.
func ipv6AddressStates() map[netip.Addr]ipv6AddressState { return nil }
