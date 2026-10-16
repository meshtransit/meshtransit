package main

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/platform/config"
)

func TestComposeEnrollmentKeysWithoutDigestKeysIsNil(t *testing.T) {
	t.Parallel()

	manager, err := composeEnrollmentKeys(nil, nil)
	if err != nil || manager != nil {
		t.Fatalf("composeEnrollmentKeys(nil digest) = %v, %v; want nil, nil", manager, err)
	}
	if _, err := composeEnrollmentKeys(nil, &config.CredentialDigestConfig{}); !errors.Is(err,
		errInvalidEnrollmentKeyComposition) {
		t.Fatalf("composeEnrollmentKeys without a pool error = %v", err)
	}
}
