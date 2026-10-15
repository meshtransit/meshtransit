package node

import "errors"

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

func allDigits(value string) bool {
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return value != ""
}
