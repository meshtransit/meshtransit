package main

import (
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
	owner.Add("first", func() error {
		order = append(order, "first")
		return firstErr
	})
	owner.Add("second", func() error {
		order = append(order, "second")
		return secondErr
	})

	err := owner.Close()
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("Close() error = %v, want both close errors", err)
	}
	if !reflect.DeepEqual(order, []string{"second", "first"}) {
		t.Fatalf("close order = %v, want [second first]", order)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
