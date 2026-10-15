// Package dnsname builds the DNS names Core gives Devices and shares.
//
// A Device is named <label>.<workspace code>.<network code>.<suffix>, its
// Network's zone being <workspace code>.<network code>.<suffix>. A share is
// named <access label>.<provider workspace code>.<provider network code>.
// shared.<suffix>. The suffix is deployment configuration (default
// mesh.internal). Names are discovery metadata only; they never grant packet
// authority.
package dnsname

import (
	"errors"
	"strings"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/node"
)

const (
	// DefaultSuffix is the suffix of a deployment that configures none.
	DefaultSuffix = "mesh.internal"
	// MaximumSuffixBytes keeps the longest name Core builds, a share name
	// <63-byte label>.<12 digits>.<12 digits>.shared.<suffix> with its
	// trailing root dot, within 253 bytes.
	MaximumSuffixBytes = 155

	maximumNameBytes = 252 // without the trailing root dot
	maximumLabel     = 63
	// storedSharedSuffix ends every share name Core derives and stores; it is
	// presented under the configured suffix instead.
	storedSharedSuffix = ".shared.mesh"
	sharedLabel        = "shared"
)

var (
	// ErrInvalidSuffix reports a suffix that is not a canonical DNS name
	// within MaximumSuffixBytes.
	ErrInvalidSuffix = errors.New("dnsname: invalid suffix")
	// ErrInvalidZone reports incomplete zone parts.
	ErrInvalidZone = errors.New("dnsname: invalid zone")
)

// Suffix is the deployment's DNS suffix: at least two lowercase labels of
// [a-z0-9-], without a trailing dot, whose last label is not all digits, and
// outside the special-use zones. Nodes answer every name under it themselves,
// so a suffix that is or covers names the host resolves elsewhere (a public
// top-level domain, local, localhost, arpa, ...) would hide them.
type Suffix struct {
	value string
}

// specialUseZones are refused as a suffix and as any parent of one: names
// under them resolve outside the mesh (RFC 6761, RFC 6762, RFC 7686, RFC
// 8375, RFC 2606).
var specialUseZones = []string{
	"local", "localhost", "arpa", "invalid", "test", "onion", "example",
	"example.com", "example.net", "example.org",
}

// ParseSuffix validates and canonicalizes a suffix to lowercase.
func ParseSuffix(value string) (Suffix, error) {
	canonical := strings.ToLower(value)
	if canonical == "" || len(canonical) > MaximumSuffixBytes || strings.TrimSpace(value) != value {
		return Suffix{}, ErrInvalidSuffix
	}
	labels := strings.Split(canonical, ".")
	for _, label := range labels {
		if !validLabel(label) {
			return Suffix{}, ErrInvalidSuffix
		}
	}
	if len(labels) < 2 || allDigits(labels[len(labels)-1]) {
		return Suffix{}, ErrInvalidSuffix
	}
	for _, zone := range specialUseZones {
		if canonical == zone || strings.HasSuffix(canonical, "."+zone) {
			return Suffix{}, ErrInvalidSuffix
		}
	}
	return Suffix{value: canonical}, nil
}

// Default returns DefaultSuffix.
func Default() Suffix { return Suffix{value: DefaultSuffix} }

// String returns the canonical suffix without a trailing dot.
func (suffix Suffix) String() string { return suffix.value }

// IsValid reports whether the value satisfies the suffix contract.
func (suffix Suffix) IsValid() bool {
	parsed, err := ParseSuffix(suffix.value)
	return err == nil && parsed == suffix
}

// SharedName presents a stored share name under this suffix: a name ending
// in .shared.mesh (every name Core derives) ends in .shared.<suffix>
// instead. Any other name, such as one a consumer typed before share names
// were derived, is returned unchanged, as is a name the rewrite would make
// too long.
func (suffix Suffix) SharedName(stored string) string {
	if !suffix.IsValid() || !strings.HasSuffix(stored, storedSharedSuffix) {
		return stored
	}
	presented := stored[:len(stored)-len(storedSharedSuffix)] + "." + sharedLabel + "." + suffix.value
	if len(presented) > maximumNameBytes {
		return stored
	}
	return presented
}

// StoredSharedName is the inverse of SharedName: a name ending in
// .shared.<suffix> is returned ending in .shared.mesh, the form Core stores
// and compares. Any other name is returned unchanged.
func (suffix Suffix) StoredSharedName(presented string) string {
	presentedSuffix := "." + sharedLabel + "." + suffix.value
	if !suffix.IsValid() || !strings.HasSuffix(presented, presentedSuffix) {
		return presented
	}
	return presented[:len(presented)-len(presentedSuffix)] + storedSharedSuffix
}

// Zone is one Network's DNS zone: <workspace code>.<network code>.<suffix>.
type Zone struct {
	value string
}

// NewZone builds the zone of the Network the display codes name.
func NewZone(workspaceCode, networkCode identity.DisplayCode, suffix Suffix) (Zone, error) {
	if !workspaceCode.IsValid() || !networkCode.IsValid() || !suffix.IsValid() {
		return Zone{}, ErrInvalidZone
	}
	return Zone{value: workspaceCode.String() + "." + networkCode.String() + "." + suffix.value}, nil
}

// String returns the zone without a trailing dot.
func (zone Zone) String() string { return zone.value }

// IsValid reports whether the zone was built by NewZone.
func (zone Zone) IsValid() bool { return zone.value != "" }

// DeviceName returns <label>.<zone> without a trailing dot. ok is false for
// an invalid zone or label.
func (zone Zone) DeviceName(label node.DNSLabel) (string, bool) {
	if !zone.IsValid() || !label.IsValid() {
		return "", false
	}
	return label.String() + "." + zone.value, true
}

// Contains reports whether name (without a trailing dot) is the zone or a
// name under it.
func (zone Zone) Contains(name string) bool {
	return zone.IsValid() && (name == zone.value || strings.HasSuffix(name, "."+zone.value))
}

func validLabel(label string) bool {
	if label == "" || len(label) > maximumLabel || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := range len(label) {
		character := label[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func allDigits(label string) bool {
	for index := range len(label) {
		if label[index] < '0' || label[index] > '9' {
			return false
		}
	}
	return true
}
