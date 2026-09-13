package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestResourceOwnerClosesInReverseOrderAndJoinsErrors(t *testing.T) {
	t.Parallel()

	firstErr := errors.New("first close failed")
	secondErr := errors.New("second close failed")
	var order []string
	owner := &resourceOwner{}
	if err := owner.Add("first", func(context.Context) error {
		order = append(order, "first")
		return firstErr
	}); err != nil {
		t.Fatalf("Add(first) error = %v", err)
	}
	if err := owner.Add("second", func(context.Context) error {
		order = append(order, "second")
		return secondErr
	}); err != nil {
		t.Fatalf("Add(second) error = %v", err)
	}

	err := owner.Close(t.Context())
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("Close() error = %v, want both close errors", err)
	}
	if !reflect.DeepEqual(order, []string{"second", "first"}) {
		t.Fatalf("close order = %v, want [second first]", order)
	}
	if err := owner.Close(t.Context()); !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("second Close() error = %v, want stable close errors", err)
	}
}

func TestResourceOwnerDoesNotStartCleanupAfterDeadline(t *testing.T) {
	t.Parallel()

	owner := &resourceOwner{}
	called := false
	if err := owner.Add("postgresql", func(context.Context) error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := owner.Close(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Close() error = %v, want context canceled", err)
	}
	if called {
		t.Fatal("resource cleanup started after the deadline was exhausted")
	}
	if err := owner.Add("redis", func(context.Context) error { return nil }); !errors.Is(err, errInvalidOwnedResource) {
		t.Fatalf("Add() after Close error = %v, want errInvalidOwnedResource", err)
	}
}
