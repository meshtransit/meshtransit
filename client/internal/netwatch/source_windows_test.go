//go:build windows

package netwatch

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDefaultRouteTokensReadHostTable(t *testing.T) {
	t.Parallel()
	tokens, indexes, err := defaultRouteTokens(nil)
	if err != nil {
		t.Fatalf("defaultRouteTokens() error = %v", err)
	}
	if len(tokens) == 0 || len(indexes) == 0 {
		t.Skip("host has no default route")
	}
	for index := range indexes {
		excludedTokens, _, err := defaultRouteTokens(map[int]struct{}{index: {}})
		if err != nil {
			t.Fatalf("defaultRouteTokens() error = %v", err)
		}
		if len(excludedTokens) >= len(tokens) {
			t.Fatalf("excluding interface %d kept tokens %v", index, excludedTokens)
		}
	}
}

func TestNativeSourceRegistersAndCloses(t *testing.T) {
	t.Parallel()
	source, err := newNativeSource(time.Second)
	if err != nil {
		t.Fatalf("newNativeSource() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := source.Wait(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := source.Wait(t.Context()); err == nil {
		t.Fatal("Wait() after Close() error = nil")
	}
}
