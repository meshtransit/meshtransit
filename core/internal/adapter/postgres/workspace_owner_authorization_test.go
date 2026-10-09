package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

func TestOwnerPublishesWithoutRoleOrApprovalAndRecordsOwnership(t *testing.T) {
	t.Parallel()
	command := policyManagementPublicationCommandFixture(t)
	database := newFakePolicyPublicationTransaction()
	enqueuePolicyPublicationSetup(database)
	database.enqueueRow(authorizePolicyPublicationSQL, policyPublicationTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = ""
			*destinations[1].(*string) = ""
			*destinations[2].(*int64) = 2
			*destinations[3].(*int64) = 1
			*destinations[4].(*int64) = 0
			*destinations[5].(*int64) = 0
			*destinations[6].(*bool) = false
			*destinations[7].(*time.Time) = policyPublicationTestTime
			*destinations[8].(*int64) = 3
			return nil
		},
	})
	enqueuePolicyPublicationResolution(t, database, command, 5, 1)
	enqueuePolicyPublicationApply(database, 6, 2)
	store := beginAuthorizedTestPolicyPublicationStore(t, database)
	value, err := store.Begin(t.Context(), command.Candidate().Snapshot().Scope())
	if err != nil {
		t.Fatal(err)
	}
	transaction := value.(*policyPublicationTransaction)
	resolution, err := transaction.Resolve(t.Context(), command, policyPublicationTestTime)
	if err != nil {
		t.Fatal("owner publication required a role or approval", err)
	}
	change := policyPublicationChangeFixture(t, command, resolution)
	if _, err := transaction.Apply(t.Context(), change); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	call := findPolicyPublicationCall(t, database.calls, appendPolicyPublicationEvidenceSQL)
	var evidence map[string]json.RawMessage
	if err := json.Unmarshal(call.arguments[14].([]byte), &evidence); err != nil {
		t.Fatal(err)
	}
	if string(evidence["workspace_owner_authority_generation"]) != "3" {
		t.Fatal("publication omitted current Workspace ownership evidence")
	}
	for _, field := range []string{"role_binding_id", "role_definition_id", "approval_evidence_id"} {
		if _, exists := evidence[field]; exists {
			t.Fatalf("owner publication invented %s", field)
		}
	}
}

func TestNetworkPermissionEvidenceDistinguishesOwnerFromRole(t *testing.T) {
	t.Parallel()
	binding := "01890f00-0000-7000-8000-000000000841"
	role := "01890f00-0000-7000-8000-000000000851"
	for _, test := range []struct {
		name            string
		binding, role   string
		ownerGeneration int64
		valid           bool
	}{
		{"role", binding, role, 0, true},
		{"owner", "", "", 3, true},
		{"absent authority", "", "", 0, false},
		{"negative owner generation", "", "", -1, false},
		{"mixed owner and role", binding, role, 3, false},
		{"partial role", binding, "", 0, false},
		{"malformed role", "invalid", role, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindingID, roleID, err := parseNetworkPermissionAuthority(test.binding, test.role, test.ownerGeneration)
			if (err == nil) != test.valid {
				t.Fatalf("authority accepted = %t, want %t", err == nil, test.valid)
			}
			if test.valid && test.ownerGeneration > 0 &&
				(bindingID != (publicid.ID{}) || roleID != (publicid.ID{})) {
				t.Fatal("owner evidence invented role identities")
			}
		})
	}
}
