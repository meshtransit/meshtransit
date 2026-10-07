package main

import (
	"errors"
	"testing"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
)

func TestAuditPartitionCompositionRejectsMissingWorkerDependencies(t *testing.T) {
	t.Parallel()
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		maintainer, err := composeAuditPartitionMaintainer(pool, discardCompositionLogger())
		if maintainer != nil || !errors.Is(err, errInvalidAuditPartitionComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	if maintainer, err := composeAuditPartitionMaintainer(&postgresadapter.Pool{}, nil); maintainer != nil ||
		!errors.Is(err, errInvalidAuditPartitionComposition) {
		t.Fatal("missing logger accepted", err)
	}
}
