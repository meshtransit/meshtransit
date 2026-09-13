package node

import (
	"errors"
	"strings"
)

const (
	maxHostnameBytes = 253
	maxDNSLabelBytes = 63
)

// ErrInvalidHostname reports an empty, non-canonical, or unsafe DNS hostname.
var ErrInvalidHostname = errors.New("node: invalid hostname")

// Hostname is a canonical lowercase ASCII DNS hostname. Unicode names must be
// converted by an explicit IDNA boundary before construction.
type Hostname struct {
	value string
}

// ParseHostname validates and canonicalizes a DNS hostname for stable
// case-insensitive allocation. A trailing root dot and surrounding whitespace
// are rejected instead of being normalized silently.
func ParseHostname(value string) (Hostname, error) {
	if len(value) == 0 || len(value) > maxHostnameBytes || strings.TrimSpace(value) != value ||
		value[len(value)-1] == '.' {
		return Hostname{}, ErrInvalidHostname
	}
	canonical := strings.ToLower(value)
	for _, label := range strings.Split(canonical, ".") {
		if !validDNSLabel(label) {
			return Hostname{}, ErrInvalidHostname
		}
	}
	return Hostname{value: canonical}, nil
}

// String returns the canonical hostname.
func (hostname Hostname) String() string { return hostname.value }

// IsValid reports whether the value satisfies the hostname contract.
func (hostname Hostname) IsValid() bool {
	validated, err := ParseHostname(hostname.value)
	return err == nil && validated == hostname
}

func validDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > maxDNSLabelBytes || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := range len(label) {
		character := label[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}
