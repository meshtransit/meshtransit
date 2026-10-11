//go:build linux || darwin

package netadmin

import (
	"errors"
	"fmt"
	"net/netip"
)

// applyRouteDiff adds the desired routes missing from current, then removes
// the current ones no longer desired. On the first failure it undoes what it
// already changed, newest first, and reports every error.
func applyRouteDiff(current, desired []netip.Prefix, apply func(netip.Prefix, bool) error) error {
	added := prefixDifference(desired, current)
	removed := prefixDifference(current, desired)
	type completedOperation struct {
		prefix netip.Prefix
		added  bool
	}
	completed := make([]completedOperation, 0, len(added)+len(removed))
	rollback := func(cause error) error {
		var rollbackErrors []error
		for index := len(completed) - 1; index >= 0; index-- {
			operation := completed[index]
			if rollbackErr := apply(operation.prefix, !operation.added); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("rolling back tun route: %w", rollbackErr))
			}
		}

		return errors.Join(append([]error{cause}, rollbackErrors...)...)
	}
	for _, prefix := range added {
		if err := apply(prefix, true); err != nil {
			return rollback(fmt.Errorf("adding tun route: %w", err))
		}
		completed = append(completed, completedOperation{prefix: prefix, added: true})
	}
	for _, prefix := range removed {
		if err := apply(prefix, false); err != nil {
			return rollback(fmt.Errorf("removing tun route: %w", err))
		}
		completed = append(completed, completedOperation{prefix: prefix})
	}

	return nil
}

func prefixDifference(left, right []netip.Prefix) []netip.Prefix {
	rightSet := make(map[netip.Prefix]struct{}, len(right))
	for _, prefix := range right {
		rightSet[prefix] = struct{}{}
	}
	difference := make([]netip.Prefix, 0, len(left))
	for _, prefix := range left {
		if _, exists := rightSet[prefix]; !exists {
			difference = append(difference, prefix)
		}
	}

	return difference
}
