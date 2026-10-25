package main

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/platform/config"
)

func TestComposeKubernetesClustersWithoutDigestKeysIsNil(t *testing.T) {
	t.Parallel()
	manager, err := composeKubernetesClusters(nil, nil)
	if manager != nil || err != nil {
		t.Fatalf("composeKubernetesClusters(nil digest) = %v, %v; want nil, nil", manager, err)
	}
	if _, err := composeKubernetesClusters(nil, &config.CredentialDigestConfig{}); !errors.Is(err,
		errInvalidKubernetesClusterComposition) {
		t.Fatalf("composeKubernetesClusters without a pool error = %v", err)
	}
}
