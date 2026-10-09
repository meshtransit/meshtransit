package creation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/workspace/creation"
)

type storeFunc func(context.Context, creation.Command) (creation.Result, error)

func (function storeFunc) Create(ctx context.Context, command creation.Command) (creation.Result, error) {
	return function(ctx, command)
}

type clockFunc func() time.Time

func (function clockFunc) Now() time.Time { return function() }

func TestNewServiceRequiresDependencies(t *testing.T) {
	t.Parallel()
	if _, err := creation.NewService(nil, clockFunc(time.Now)); !errors.Is(err, creation.ErrInvalid) {
		t.Fatal("nil store accepted")
	}
	service, err := creation.NewService(storeFunc(func(context.Context, creation.Command) (creation.Result, error) {
		return creation.Result{DisplayCode: identity.DisplayCode("000000000001")}, nil
	}), clockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(t.Context(), creation.Command{}); !errors.Is(err, creation.ErrInvalid) {
		t.Fatal("invalid command reached the store")
	}
}
