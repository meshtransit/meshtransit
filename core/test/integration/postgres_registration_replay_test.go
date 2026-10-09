//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

func assertPostgreSQLRegistrationReplay(
	ctx context.Context,
	t *testing.T,
	store *postgresadapter.RegistrationReplayStore,
	command registrationapp.Command,
) {
	t.Helper()

	result, found, err := store.ResolveCommitted(ctx, command)
	if err != nil {
		t.Fatalf("RegistrationReplayStore.ResolveCommitted() error = %v", err)
	}
	if !found || result.RegistrationID() != command.RegistrationID ||
		result.Scope() != command.Scope ||
		result.NodeID().String() != "01890f10-0000-7000-8000-000000000603" ||
		result.Hostname().String() != "node-one.example" ||
		result.Disposition() != registrationapp.DispositionCreated ||
		result.NetworkRevision() != 3 {
		t.Fatalf("registration replay result = (%+v, found=%t), want exact durable snapshot", result, found)
	}

	conflict := command
	conflictingNodeKey, err := node.NewKey(filledIntegrationKey(0x23))
	if err != nil {
		t.Fatalf("construct conflicting integration Node key: %v", err)
	}
	conflict.Identity, err = node.NewRegistrationIdentity(
		command.Identity.MachineKey(),
		conflictingNodeKey,
	)
	if err != nil {
		t.Fatalf("construct conflicting integration identity: %v", err)
	}
	_, found, err = store.ResolveCommitted(ctx, conflict)
	if found || !errors.Is(err, registrationapp.ErrIntentConflict) {
		t.Fatalf("conflicting registration replay = (found=%t, error=%v), want intent conflict", found, err)
	}
}
