//go:build !dexbroker

package main

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

func TestIdentityBrokerCompositionFailsClosedWithoutBuildSupport(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := composeIdentityBroker(t.Context(), config.IdentityConfig{}, &resourceOwner{}, logger)
	if !errors.Is(err, errIdentityBrokerUnavailable) {
		t.Fatalf("composeIdentityBroker() error = %v, want unavailable", err)
	}
}
