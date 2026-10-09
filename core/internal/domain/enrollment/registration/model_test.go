package registration_test

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

func TestNewChangePreservesCredentialCustody(t *testing.T) {
	t.Parallel()

	params := validChangeParams(t)
	change, err := registration.NewChange(params)
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	if change.OwnerID() != params.Credential.IssuerID() ||
		change.CustodianID() != params.Credential.IssuerID() {
		t.Fatal("NewChange() did not preserve credential issuer ownership and custody")
	}
}

func TestNewChangeRejectsAuthorityWidening(t *testing.T) {
	t.Parallel()

	otherPrincipal, err := identity.ParsePrincipalID("01890f20-0000-7000-8000-000000000007")
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*registration.ChangeParams)
	}{
		{
			name: "missing owner",
			mutate: func(params *registration.ChangeParams) {
				params.OwnerID = identity.PrincipalID{}
			},
		},
		{
			name: "different owner",
			mutate: func(params *registration.ChangeParams) {
				params.OwnerID = otherPrincipal
			},
		},
		{
			name: "different custodian",
			mutate: func(params *registration.ChangeParams) {
				params.CustodianID = otherPrincipal
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := validChangeParams(t)
			test.mutate(&params)
			change, err := registration.NewChange(params)
			if !errors.Is(err, registration.ErrInvalidChange) {
				t.Fatalf("NewChange() error = %v, want ErrInvalidChange", err)
			}
			if change.IsValid() {
				t.Fatal("invalid Change is valid")
			}
		})
	}
}

func validChangeParams(t *testing.T) registration.ChangeParams {
	t.Helper()

	command := mustCommand(t)
	resolution := mustOpenResolution(t, command, node.ID{})
	credential, err := resolution.Credential().Consume(fixtureTime, command.RecoveryEpoch)
	if err != nil {
		t.Fatalf("Credential.Consume() error = %v", err)
	}
	nodeID := mustNodeID(t, "01890f20-0000-7000-8000-000000000008")
	state, err := resolution.Registration().Authorize(fixtureTime)
	if err != nil {
		t.Fatalf("Registration.Authorize() error = %v", err)
	}
	state, err = state.Complete(nodeID, fixtureTime)
	if err != nil {
		t.Fatalf("Registration.Complete() error = %v", err)
	}
	return registration.ChangeParams{
		Registration: state,
		Profile:      resolution.Profile(),
		Credential:   credential,
		Identity:     command.Identity,
		OwnerID:      credential.IssuerID(),
		CustodianID:  credential.IssuerID(),
		NodeID:       nodeID,
		Hostname:     command.Hostname,
		Disposition:  registration.DispositionCreated,
		MutationIDs:  mustMutationIDs(t),
		OccurredAt:   fixtureTime,
	}
}
