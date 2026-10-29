package main

import (
	"errors"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

func TestKubeOperationPartitionCompositionRejectsMissingWorkerDependencies(t *testing.T) {
	t.Parallel()
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		maintainer, metrics, err := composeKubeOperationPartitions(pool, discardCompositionLogger())
		if maintainer != nil || metrics != nil || !errors.Is(err, errInvalidKubeAuditComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	if maintainer, _, err := composeKubeOperationPartitions(&postgresadapter.Pool{}, nil); maintainer != nil ||
		!errors.Is(err, errInvalidKubeAuditComposition) {
		t.Fatal("missing logger accepted", err)
	}
}
