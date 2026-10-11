package node

import (
	"errors"
	"strconv"
	"strings"
)

// MaximumHostnameFamily bounds the Devices of one Network that may share a
// requested hostname (and so its numbered variants); it matches the largest
// Network inventory.
const MaximumHostnameFamily = 200_000

const maxHostnameAllocationSnapshot = MaximumHostnameFamily

// ErrInvalidHostnameAllocation reports malformed or unbounded allocation input.
var ErrInvalidHostnameAllocation = errors.New("node: invalid hostname allocation")

// NextAvailableHostname returns the lowest collision-free numeric variant of
// requested. The caller must load occupied names under the durable allocation
// lock and rely on the database uniqueness constraint as the final arbiter.
func NextAvailableHostname(requested Hostname, occupied []Hostname) (Hostname, error) {
	if !requested.IsValid() || len(occupied) > maxHostnameAllocationSnapshot {
		return Hostname{}, ErrInvalidHostnameAllocation
	}

	taken := make(map[string]struct{}, len(occupied))
	for _, hostname := range occupied {
		if !hostname.IsValid() {
			return Hostname{}, ErrInvalidHostnameAllocation
		}
		taken[hostname.value] = struct{}{}
	}

	for ordinal := range len(occupied) + 1 {
		candidate, err := hostnameCandidate(requested, ordinal)
		if err != nil {
			return Hostname{}, err
		}
		if _, exists := taken[candidate.value]; !exists {
			return candidate, nil
		}
	}
	return Hostname{}, ErrInvalidHostnameAllocation
}

func hostnameCandidate(requested Hostname, ordinal int) (Hostname, error) {
	if !requested.IsValid() || ordinal < 0 || ordinal > maxHostnameAllocationSnapshot {
		return Hostname{}, ErrInvalidHostnameAllocation
	}
	if ordinal == 0 {
		return requested, nil
	}

	suffix := "-" + strconv.Itoa(ordinal)
	firstLabel, remainder, _ := strings.Cut(requested.value, ".")
	if remainder != "" {
		remainder = "." + remainder
	}
	stemBytes := min(
		len(firstLabel),
		maxDNSLabelBytes-len(suffix),
		maxHostnameBytes-len(remainder)-len(suffix),
	)
	if stemBytes < 1 {
		return Hostname{}, ErrInvalidHostnameAllocation
	}

	candidate, err := ParseHostname(firstLabel[:stemBytes] + suffix + remainder)
	if err != nil {
		return Hostname{}, ErrInvalidHostnameAllocation
	}
	return candidate, nil
}

// HostnameFamilyPrefix returns the prefix shared by requested and every
// numbered variant NextAvailableHostname may choose for it. Reading only the
// occupied hostnames with that prefix is enough to choose exactly as when
// reading every hostname of the Network; the prefix may match more names,
// which are then simply not candidates.
func HostnameFamilyPrefix(requested Hostname) (string, error) {
	if !requested.IsValid() {
		return "", ErrInvalidHostnameAllocation
	}
	longestSuffix := len("-" + strconv.Itoa(maxHostnameAllocationSnapshot))
	firstLabel, remainder, _ := strings.Cut(requested.value, ".")
	if remainder != "" {
		remainder = "." + remainder
	}
	stemBytes := min(len(firstLabel), maxDNSLabelBytes-longestSuffix, maxHostnameBytes-len(remainder)-longestSuffix)
	if stemBytes < 1 {
		return "", ErrInvalidHostnameAllocation
	}
	return firstLabel[:stemBytes], nil
}
