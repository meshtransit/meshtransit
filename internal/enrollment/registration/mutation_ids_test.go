package registration_test

import (
	"errors"
	"testing"

	registration "github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestNewMutationIDs(t *testing.T) {
	t.Parallel()

	params := mutationIDParams(t)
	ids, err := registration.NewMutationIDs(params)
	if err != nil {
		t.Fatalf("registration.NewMutationIDs() error = %v", err)
	}
	if !ids.IsValid() {
		t.Fatal("MutationIDs.IsValid() = false")
	}
	tests := []struct {
		name string
		got  publicid.ID
		want publicid.ID
	}{
		{name: "change", got: ids.ChangeID(), want: params.ChangeID},
		{name: "audit event", got: ids.AuditEventID(), want: params.AuditEventID},
		{name: "outbox event", got: ids.OutboxEventID(), want: params.OutboxEventID},
		{name: "credential use", got: ids.CredentialUseID(), want: params.CredentialUseID},
		{name: "machine key epoch", got: ids.MachineKeyEpochID(), want: params.MachineKeyEpochID},
		{name: "Node key epoch", got: ids.NodeKeyEpochID(), want: params.NodeKeyEpochID},
		{name: "IPv4 lease", got: ids.IPv4LeaseID(), want: params.IPv4LeaseID},
		{name: "IPv6 lease", got: ids.IPv6LeaseID(), want: params.IPv6LeaseID},
	}
	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("%s ID = %s, want %s", test.name, test.got, test.want)
		}
	}
}

func TestNewMutationIDsRejectsIncompleteOrDuplicateValues(t *testing.T) {
	t.Parallel()

	valid := mutationIDParams(t)
	tests := []struct {
		name   string
		mutate func(*registration.MutationIDParams)
	}{
		{
			name: "missing change ID",
			mutate: func(params *registration.MutationIDParams) {
				params.ChangeID = publicid.ID{}
			},
		},
		{
			name: "missing IPv6 lease ID",
			mutate: func(params *registration.MutationIDParams) {
				params.IPv6LeaseID = publicid.ID{}
			},
		},
		{
			name: "duplicate evidence IDs",
			mutate: func(params *registration.MutationIDParams) {
				params.OutboxEventID = params.AuditEventID
			},
		},
		{
			name: "duplicate child IDs",
			mutate: func(params *registration.MutationIDParams) {
				params.NodeKeyEpochID = params.MachineKeyEpochID
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := valid
			test.mutate(&params)
			if _, err := registration.NewMutationIDs(params); !errors.Is(
				err,
				registration.ErrInvalidMutationIDs,
			) {
				t.Fatalf("registration.NewMutationIDs() error = %v, want ErrInvalidMutationIDs", err)
			}
		})
	}
}
