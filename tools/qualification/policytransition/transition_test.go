package main

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestBuildPublicationCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantRules int
	}{
		{name: "bidirectional icmp", args: validAllowArgs(), wantRules: 2},
		{name: "deny", args: validDenyArgs(), wantRules: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			spec, err := parseTransitionSpec(
				test.args,
				lookupFromMap(map[string]string{envConfirmation: testNetworkID}),
			)
			if err != nil {
				t.Fatalf("parseTransitionSpec() error = %v", err)
			}
			ids := []string{
				"01890f00-0000-7000-8000-000000000801",
				"01890f00-0000-7000-8000-000000000802",
			}
			index := 0
			command, err := buildPublicationCommand(spec, func() (publicid.ID, error) {
				if index >= len(ids) {
					return publicid.ID{}, errors.New("too many ids requested")
				}
				id, parseErr := publicid.Parse(ids[index])
				index++
				return id, parseErr
			})
			if err != nil {
				t.Fatalf("buildPublicationCommand() error = %v", err)
			}
			snapshot := command.Candidate().Snapshot()
			rules := snapshot.Rules()
			if snapshot.Revision() != 12 || len(rules) != test.wantRules ||
				command.BasePolicyRevision() != 11 {
				t.Fatalf("buildPublicationCommand() snapshot = %+v", snapshot)
			}
			if test.wantRules == 2 {
				if rules[0].SourceNodeID() != rules[1].DestinationNodeID() ||
					rules[0].DestinationNodeID() != rules[1].SourceNodeID() {
					t.Fatal("bidirectional rules did not reverse source and destination")
				}
			}
		})
	}
}

func TestBuildPublicationCommandPropagatesIDFailure(t *testing.T) {
	t.Parallel()

	spec, err := parseTransitionSpec(
		validAllowArgs(),
		lookupFromMap(map[string]string{envConfirmation: testNetworkID}),
	)
	if err != nil {
		t.Fatalf("parseTransitionSpec() error = %v", err)
	}
	wantErr := errors.New("entropy unavailable")
	if _, err := buildPublicationCommand(spec, func() (publicid.ID, error) {
		return publicid.ID{}, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("buildPublicationCommand() error = %v, want entropy error", err)
	}
}

func TestBuildPublicationCommandRejectsInvalidInternalSpec(t *testing.T) {
	t.Parallel()

	if _, err := buildPublicationCommand(transitionSpec{}, publicid.New); !errors.Is(err, errInvalidInput) {
		t.Fatalf("buildPublicationCommand() error = %v, want errInvalidInput", err)
	}
}
