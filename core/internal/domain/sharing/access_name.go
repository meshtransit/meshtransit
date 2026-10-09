package sharing

import (
	"errors"
	"net/netip"
	"strings"
)

const (
	maximumAccessNameBytes = 253
	maximumDNSLabelBytes   = 63
)

// ErrInvalidAccessName reports a non-canonical or unsafe consumer DNS name.
var ErrInvalidAccessName = errors.New("sharing: invalid access name")

// AccessName is a canonical consumer-local DNS name. It is discovery
// metadata only; authorization remains bound to the Imported Resource,
// Trust Contract, endpoint generation, and traffic constraints.
type AccessName struct {
	value string
}

// ParseAccessName validates and canonicalizes a fully qualified DNS name.
// Unicode names require an explicit IDNA conversion at the API boundary.
// IP literals, trailing root dots, and relative single-label names are denied.
func ParseAccessName(value string) (AccessName, error) {
	if len(value) == 0 || len(value) > maximumAccessNameBytes ||
		strings.TrimSpace(value) != value || value[len(value)-1] == '.' {
		return AccessName{}, ErrInvalidAccessName
	}
	canonical := strings.ToLower(value)
	if !strings.Contains(canonical, ".") || isNumericAccessName(canonical) {
		return AccessName{}, ErrInvalidAccessName
	}
	if _, err := netip.ParseAddr(canonical); err == nil {
		return AccessName{}, ErrInvalidAccessName
	}
	for _, label := range strings.Split(canonical, ".") {
		if !validAccessNameLabel(label) {
			return AccessName{}, ErrInvalidAccessName
		}
	}
	return AccessName{value: canonical}, nil
}

// String returns the lowercase canonical DNS name.
func (name AccessName) String() string { return name.value }

// IsValid reports whether the value satisfies the access-name contract.
func (name AccessName) IsValid() bool {
	validated, err := ParseAccessName(name.value)
	return err == nil && validated == name
}

func validAccessNameLabel(label string) bool {
	if len(label) == 0 || len(label) > maximumDNSLabelBytes ||
		label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := range len(label) {
		character := label[index]
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func isNumericAccessName(value string) bool {
	for index := range len(value) {
		character := value[index]
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
