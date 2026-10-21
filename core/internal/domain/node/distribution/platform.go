package distribution

import (
	"net/netip"
	"unicode"
	"unicode/utf8"
)

// MaximumPublicAddresses bounds the public addresses kept of one report.
const MaximumPublicAddresses = 4

// maximumPlatformField bounds each field of a Platform, in bytes.
const maximumPlatformField = 64

// Platform is what a Device's client says it runs on, from the hello of
// its current session: an operating system as Go names it (darwin, linux,
// windows, android, ios, freebsd), its version when the client sends one,
// the CPU architecture and the client version.
type Platform struct {
	OS            string
	OSVersion     string
	Arch          string
	ClientVersion string
}

// IsValid reports a Platform with an OS and short printable fields.
func (platform Platform) IsValid() bool {
	if platform.OS == "" {
		return false
	}
	for _, field := range []string{platform.OS, platform.OSVersion, platform.Arch, platform.ClientVersion} {
		if !printableField(field) {
			return false
		}
	}
	return true
}

func printableField(text string) bool {
	if len(text) > maximumPlatformField || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// carrierGradeNAT is the shared address space of RFC 6598.
var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// IsPublicAddress reports an address on the public Internet: global
// unicast, neither private (RFC 1918, ULA) nor carrier-grade NAT, in
// canonical form.
func IsPublicAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && address == address.Unmap() &&
		address.IsGlobalUnicast() && !address.IsPrivate() && !carrierGradeNAT.Contains(address)
}

// validPublicAddresses reports distinct public addresses, IPv4 first.
func validPublicAddresses(addresses []netip.Addr) bool {
	if len(addresses) > MaximumPublicAddresses {
		return false
	}
	for index, address := range addresses {
		if !IsPublicAddress(address) {
			return false
		}
		if index > 0 && addresses[index-1].Compare(address) >= 0 {
			return false
		}
	}
	return true
}
