package main

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/platform/config"
)

func TestComposeClusterJoinsNeedsARuntimePool(t *testing.T) {
	t.Parallel()
	if joins, err := composeClusterJoins(config.EnrollmentConfig{}, nil); joins != nil ||
		!errors.Is(err, errInvalidKubernetesJoinComposition) {
		t.Fatalf("composeClusterJoins(nil pool) = %v, %v", joins, err)
	}
}
