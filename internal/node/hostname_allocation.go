package node

import (
	"errors"
	"strconv"
	"strings"
)

const maxHostnameAllocationSnapshot = 1024

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
