package main

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestRecordDeploymentEntitlementIsOptional(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	code, err := recordDeploymentEntitlement(t.Context(), nil, nil, logger, time.Now())
	if err != nil || code != "" {
		t.Fatalf("absent entitlement settings failed startup: %s %v", code, err)
	}
}
