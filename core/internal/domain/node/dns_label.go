package node

import (
	"errors"
	"strings"
)

// ErrInvalidDNSLabel reports a value that is not one canonical Device DNS label.
var ErrInvalidDNSLabel = errors.New("node: invalid DNS label")

// DNSLabel is the first label of a Device's DNS name
// (<label>.<workspace code>.<network code>.<suffix>). Core derives it from the
// hostname and keeps it unique among the live Devices of one Network; the
// database assigns it. Like every name, it is discovery metadata and grants
// no packet authority.
type DNSLabel struct {
	value string
}

// ParseDNSLabel accepts exactly one canonical lowercase DNS label: 1 to 63
// bytes of [a-z0-9-], no leading or trailing hyphen, not all digits.
func ParseDNSLabel(value string) (DNSLabel, error) {
	if !validDNSLabel(value) || allDigits(value) {
		return DNSLabel{}, ErrInvalidDNSLabel
	}
	return DNSLabel{value: value}, nil
}

// String returns the canonical label.
func (label DNSLabel) String() string { return label.value }

// IsValid reports whether the value satisfies the label contract.
func (label DNSLabel) IsValid() bool {
	_, err := ParseDNSLabel(label.value)
	return err == nil
}

// fallbackDNSLabel names a Device whose hostname gives no usable label, and
// prefixes an all-digit or reserved one.
const fallbackDNSLabel = "device"

// reservedDNSLabels are names hosts and browsers look up on their own (proxy
// and tunnel autodiscovery, local host names, common service names). A
// Device's label is completed with the Network's zone as search domain, so a
// Device must never claim one of them: it is prefixed with "device-".
var reservedDNSLabels = map[string]struct{}{
	"autoconfig": {}, "autodiscover": {}, "broadcasthost": {}, "dns": {}, "gateway": {}, "imap": {},
	"ip6-localhost": {}, "ip6-loopback": {}, "isatap": {}, "local": {}, "localdomain": {}, "localhost": {},
	"mail": {}, "ns": {}, "ntp": {}, "pop": {}, "proxy": {}, "router": {}, "smtp": {}, "wpad": {}, "www": {},
}

// DeriveDNSLabel is the label a hostname gives before deduplication; the
// database's mesh_ops.derive_device_dns_label_v1 computes the same. It takes
// the first hostname label, lowercased, replaces each run of other
// characters with one hyphen (so no label starts with an IDNA "xn--"
// prefix), trims hyphens and truncates to 63 bytes. Nothing left gives
// "device"; an all-digit or reserved result is prefixed with "device-".
func DeriveDNSLabel(hostname string) DNSLabel {
	first, _, _ := strings.Cut(strings.Trim(hostname, " "), ".")
	var builder strings.Builder
	hyphen := false
	for _, character := range strings.ToLower(first) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			builder.WriteRune(character)
			hyphen = false
			continue
		}
		if !hyphen {
			builder.WriteByte('-')
			hyphen = true
		}
	}
	label := truncateDNSLabel(strings.Trim(builder.String(), "-"))
	if _, reserved := reservedDNSLabels[label]; reserved || allDigits(label) {
		label = truncateDNSLabel(fallbackDNSLabel + "-" + label)
	}
	if label == "" {
		label = fallbackDNSLabel
	}
	return DNSLabel{value: label}
}

func truncateDNSLabel(label string) string {
	if len(label) <= maxDNSLabelBytes {
		return label
	}
	return strings.TrimRight(label[:maxDNSLabelBytes], "-")
}

func allDigits(value string) bool {
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return value != ""
}
