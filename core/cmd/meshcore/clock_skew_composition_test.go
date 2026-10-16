package main

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

func TestComposeClockSkewObserverRequiresAPoolAndLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if _, err := composeClockSkewObserver(postgresPools{}, logger); !errors.Is(err, errInvalidClockSkewComposition) {
		t.Fatalf("composeClockSkewObserver(no pool) error = %v", err)
	}
	pools := postgresPools{worker: &postgresadapter.Pool{}}
	if _, err := composeClockSkewObserver(pools, nil); !errors.Is(err, errInvalidClockSkewComposition) {
		t.Fatalf("composeClockSkewObserver(no logger) error = %v", err)
	}
	if observer, err := composeClockSkewObserver(pools, logger); err != nil || observer == nil {
		t.Fatalf("composeClockSkewObserver(worker) = %v, %v", observer, err)
	}
}
