package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/config"
)

const (
	testWorkspaceID       = "01890f00-0000-7000-8000-000000000101"
	testNetworkID         = "01890f00-0000-7000-8000-000000000201"
	testActorID           = "01890f00-0000-7000-8000-000000000011"
	testSourceNodeID      = "01890f00-0000-7000-8000-000000000701"
	testDestinationNodeID = "01890f00-0000-7000-8000-000000000702"
)

func TestParseTransitionSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		args         []string
		confirmation string
		wantMode     transitionMode
		wantError    bool
	}{
		{
			name:         "bidirectional icmp",
			args:         validAllowArgs(),
			confirmation: testNetworkID,
			wantMode:     transitionModeBidirectionalICMP,
		},
		{
			name:         "deny",
			args:         validDenyArgs(),
			confirmation: testNetworkID,
			wantMode:     transitionModeDeny,
		},
		{
			name:         "wrong confirmation",
			args:         validDenyArgs(),
			confirmation: testWorkspaceID,
			wantError:    true,
		},
		{
			name:         "deny rejects unused node",
			args:         append(validDenyArgs(), "--source-node-id", testSourceNodeID),
			confirmation: testNetworkID,
			wantError:    true,
		},
		{
			name: "same source and destination",
			args: replaceArgument(
				validAllowArgs(),
				"--destination-node-id",
				testSourceNodeID,
			),
			confirmation: testNetworkID,
			wantError:    true,
		},
		{
			name:         "positional argument",
			args:         append(validDenyArgs(), "unexpected"),
			confirmation: testNetworkID,
			wantError:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lookup := lookupFromMap(map[string]string{envConfirmation: test.confirmation})
			spec, err := parseTransitionSpec(test.args, lookup)
			if test.wantError {
				if !errors.Is(err, errInvalidInput) {
					t.Fatalf("parseTransitionSpec() error = %v, want errInvalidInput", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTransitionSpec() error = %v", err)
			}
			if spec.mode != test.wantMode || spec.basePolicyRevision != 11 ||
				spec.scope.NetworkID().String() != testNetworkID {
				t.Fatalf("parseTransitionSpec() = %+v", spec)
			}
		})
	}
}

func TestRunWritesOnlySafeStructuredResult(t *testing.T) {
	t.Parallel()

	values := validEnvironment()
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := run(
		t.Context(),
		validDenyArgs(),
		lookupFromMap(values),
		&output,
		&errorOutput,
		func(
			_ context.Context,
			spec transitionSpec,
			database databaseSettings,
		) (transitionOutput, error) {
			if spec.mode != transitionModeDeny || database.address != "database.example:5432" {
				t.Fatal("executor received invalid validated input")
			}
			return transitionOutput{
				Mode:            "deny",
				RuleCount:       0,
				PolicyRevision:  12,
				NetworkRevision: 16,
				ReleaseID:       "01890f00-0000-7000-8000-000000000901",
			}, nil
		},
	)
	if exitCode != exitSuccess || errorOutput.Len() != 0 {
		t.Fatalf("run() exit/stderr = %d/%q", exitCode, errorOutput.String())
	}
	result := transitionOutput{}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if result.PolicyRevision != 12 || result.RuleCount != 0 || result.Mode != "deny" {
		t.Fatalf("run() output = %+v", result)
	}
}

func TestRunRedactsExecutionFailure(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	exitCode := run(
		t.Context(),
		validDenyArgs(),
		lookupFromMap(validEnvironment()),
		&output,
		&errorOutput,
		func(context.Context, transitionSpec, databaseSettings) (transitionOutput, error) {
			return transitionOutput{}, errors.New("database.example:5432 secret-path")
		},
	)
	if exitCode != exitFailure || output.Len() != 0 ||
		errorOutput.String() != "policytransition: publication failed\n" {
		t.Fatalf("run() exit/stdout/stderr = %d/%q/%q", exitCode, output.String(), errorOutput.String())
	}
}

func validAllowArgs() []string {
	return []string{
		"--workspace-id", testWorkspaceID,
		"--network-id", testNetworkID,
		"--actor-principal-id", testActorID,
		"--base-policy-revision", "11",
		"--mode", "bidirectional-icmp",
		"--source-node-id", testSourceNodeID,
		"--destination-node-id", testDestinationNodeID,
		"--audit-reason", "qualification allow transition",
	}
}

func validDenyArgs() []string {
	return []string{
		"--workspace-id", testWorkspaceID,
		"--network-id", testNetworkID,
		"--actor-principal-id", testActorID,
		"--base-policy-revision", "11",
		"--mode", "deny",
		"--audit-reason", "qualification deny transition",
	}
}

func validEnvironment() map[string]string {
	// #nosec G101 -- these synthetic values are file references, not credentials.
	return map[string]string{
		envConfirmation:           testNetworkID,
		envPostgreSQLAddress:      "database.example:5432",
		envPostgreSQLDatabase:     "meshtransit",
		envPostgreSQLUser:         "mesh_runtime",
		envPostgreSQLPasswordFile: "/run/secrets/postgres-password",
		envPostgreSQLTrustFile:    "/run/trust/postgres-ca.pem",
	}
}

func lookupFromMap(values map[string]string) config.LookupFunc {
	return func(key string) (string, bool) {
		value, found := values[key]
		return value, found
	}
}

func replaceArgument(args []string, name, value string) []string {
	replaced := append([]string(nil), args...)
	for index := range replaced {
		if replaced[index] == name && index+1 < len(replaced) {
			replaced[index+1] = value
			return replaced
		}
	}
	return replaced
}
