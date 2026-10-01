package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestBrowserWorkspaceChoicesRejectMalformedOrUnorderedInventory(t *testing.T) {
	t.Parallel()
	const first = `{"workspace_id":"01890f00-0000-7000-8000-000000000103","display_name":"Owned"}`
	const second = `{"workspace_id":"01890f00-0000-7000-8000-000000000104","display_name":"Invited"}`
	for _, test := range []struct {
		name, encoded string
		limit         int
		valid         bool
	}{
		{name: "multiple memberships", encoded: `{"workspaces":[` + first + `,` + second + `]}`, limit: 100, valid: true},
		{name: "empty inventory", encoded: `{"workspaces":[]}`, limit: 100, valid: true},
		{name: "missing inventory", encoded: `{}`, limit: 100},
		{name: "duplicate Workspace", encoded: `{"workspaces":[` + first + `,` + first + `]}`, limit: 100},
		{name: "reverse order", encoded: `{"workspaces":[` + second + `,` + first + `]}`, limit: 100},
		{name: "unbounded page", encoded: `{"workspaces":[` + first + `,` + second + `]}`, limit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			choices, err := decodeBrowserWorkspaceChoices(test.encoded, workspace.ID{}, test.limit)
			if test.valid {
				if err != nil || !choices.IsValid() {
					t.Fatalf("Workspace inventory = (%+v, %v)", choices, err)
				}
			} else if !errors.Is(err, ErrBrowserEnrollmentChoicesEvidence) {
				t.Fatalf("malformed Workspace inventory accepted: %v", err)
			}
		})
	}
}

func TestBrowserWorkspaceNetworkReaderBindsSelectedScope(t *testing.T) {
	t.Parallel()
	selected, err := workspace.ParseID("01890f00-0000-7000-8000-000000000104")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, encoded string
		valid         bool
	}{
		{name: "exact Workspace", encoded: `{"workspace_id":"01890f00-0000-7000-8000-000000000104","workspace_display_name":"Invited","networks":[]}`, valid: true},
		{name: "substituted Workspace", encoded: `{"workspace_id":"01890f00-0000-7000-8000-000000000103","workspace_display_name":"Owned","networks":[]}`},
		{name: "missing Workspace name", encoded: `{"workspace_id":"01890f00-0000-7000-8000-000000000104","networks":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{&test.encoded}}}
			store, err := newAccountSessionStore(&fakeAccountSessionDatabase{transaction: transaction},
				AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, nil)
			if err != nil {
				t.Fatal(err)
			}
			choices, found, err := store.ReadBrowserEnrollmentNetworksInWorkspace(t.Context(),
				accountSessionDeploymentID(t), 7, accountSessionDigest(t), selected, network.ID{}, 100)
			if test.valid {
				if err != nil || !found || choices.WorkspaceID != selected {
					t.Fatalf("scope = (%+v, %v, %v)", choices, found, err)
				}
			} else if !errors.Is(err, ErrBrowserEnrollmentChoicesEvidence) || found {
				t.Fatal("substituted scope accepted")
			}
			if transaction.arguments[4] != selected.String() {
				t.Fatal("selected Workspace was not sent as exact SQL filter")
			}
		})
	}
}
