package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

func TestIssueScopeValidation(t *testing.T) {
	t.Parallel()
	scope := validIssueScope()
	if !scope.isValid() {
		t.Fatal("valid issue scope was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*issueScope)
	}{
		{name: "cloud deployment", mutate: func(value *issueScope) { value.deploymentProfile = "saas" }},
		{name: "recovery quarantine", mutate: func(value *issueScope) { value.deploymentRecoveryState = "quarantined" }},
		{name: "inactive network", mutate: func(value *issueScope) { value.networkState = "suspended" }},
		{name: "wrong issuer", mutate: func(value *issueScope) { value.profileCreatorInternalID++ }},
		{name: "ephemeral profile", mutate: func(value *issueScope) { value.ephemeralMode = "ephemeral" }},
		{name: "reusable profile", mutate: func(value *issueScope) { value.credentialMaxUses = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := scope
			test.mutate(&candidate)
			if candidate.isValid() {
				t.Fatalf("issueScope accepted %s", test.name)
			}
		})
	}
}

func TestNewIssueIDsRequiresDistinctUUIDv7Values(t *testing.T) {
	t.Parallel()
	index := 0
	ids, err := newIssueIDs(func() (publicid.ID, error) {
		index++
		return publicid.Parse(fmt.Sprintf("01995d00-0000-7000-8000-%012d", index))
	})
	if err != nil {
		t.Fatalf("newIssueIDs() error = %v", err)
	}
	if !ids.isValid() || ids.change == ids.event || ids.credential == ids.outbox {
		t.Fatalf("newIssueIDs() returned invalid or duplicate values: %#v", ids)
	}
	one, err := publicid.Parse("01995d00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse duplicate ID: %v", err)
	}
	if _, err := newIssueIDs(func() (publicid.ID, error) { return one, nil }); !errors.Is(err, errInvalidInput) {
		t.Fatalf("newIssueIDs() duplicate error = %v, want invalid input", err)
	}
}

func validIssueScope() issueScope {
	return issueScope{
		deploymentInternalID:     1,
		deploymentProfile:        "self_hosted",
		recoveryEpoch:            1,
		deploymentState:          "active",
		deploymentRecoveryState:  "verified",
		principalInternalID:      11,
		principalKind:            "account",
		principalState:           "active",
		principalGeneration:      1,
		workspaceInternalID:      101,
		workspaceState:           "active",
		workspaceGeneration:      1,
		networkInternalID:        201,
		networkState:             "active",
		networkGeneration:        1,
		networkRevision:          18,
		profileInternalID:        601,
		profileCreatorInternalID: 11,
		profileState:             "active",
		nodeLifetimeSeconds:      86400,
		ephemeralMode:            "persistent",
		credentialUsePolicy:      "bounded",
		credentialMaxUses:        1,
		profileVersion:           1,
	}
}
