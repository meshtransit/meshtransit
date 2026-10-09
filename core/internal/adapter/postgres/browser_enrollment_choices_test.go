package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

func TestReadBrowserEnrollmentNetworksKeepsEmptyChoicesDistinctFromMissingSession(t *testing.T) {
	t.Parallel()
	encoded := `{"workspace_id":"01890f00-0000-7000-8000-000000000103","networks":[]}`
	for _, test := range []struct {
		name  string
		value *string
		found bool
	}{
		{name: "admitted with no eligible Network", value: &encoded, found: true},
		{name: "session not admitted", value: nil, found: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{test.value}}}
			store, err := newAccountSessionStore(&fakeAccountSessionDatabase{transaction: transaction},
				AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second}, nil)
			if err != nil {
				t.Fatalf("newAccountSessionStore() error = %v", err)
			}
			choices, found, err := store.ReadBrowserEnrollmentNetworks(t.Context(),
				accountSessionDeploymentID(t), 7, accountSessionDigest(t), network.ID{}, 100)
			if err != nil || found != test.found || transaction.commits != 1 ||
				transaction.rollbacks != 0 || len(choices.Networks) != 0 {
				t.Fatalf("ReadBrowserEnrollmentNetworks() = (%+v, %v, %v), commit/rollback=%d/%d",
					choices, found, err, transaction.commits, transaction.rollbacks)
			}
			if found && choices.WorkspaceID.String() != "01890f00-0000-7000-8000-000000000103" {
				t.Fatal("admitted choice result lost Workspace identity")
			}
		})
	}
}

func TestBrowserEnrollmentChoicesRejectMalformedAuthority(t *testing.T) {
	t.Parallel()
	const workspaceID = `"workspace_id":"01890f00-0000-7000-8000-000000000103"`
	const first = `{"network_id":"01890f00-0000-7000-8000-000000000203","display_name":"First"}`
	const second = `{"network_id":"01890f00-0000-7000-8000-000000000204","display_name":"Second"}`
	after, err := network.ParseID("01890f00-0000-7000-8000-000000000203")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		encoded string
		after   network.ID
		limit   int
	}{
		{name: "missing array", encoded: `{` + workspaceID + `}`, limit: 100},
		{name: "invalid Workspace", encoded: `{"workspace_id":"wrong","networks":[]}`, limit: 100},
		{name: "duplicate Network", encoded: `{` + workspaceID + `,"networks":[` + first + `,` + first + `]}`, limit: 100},
		{name: "out of order", encoded: `{` + workspaceID + `,"networks":[` + second + `,` + first + `]}`, limit: 100},
		{name: "before cursor", encoded: `{` + workspaceID + `,"networks":[` + first + `]}`, after: after, limit: 100},
		{name: "over page limit", encoded: `{` + workspaceID + `,"networks":[` + first + `,` + second + `]}`, limit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeBrowserEnrollmentChoices(test.encoded, test.after, test.limit)
			if !errors.Is(err, ErrBrowserEnrollmentChoicesEvidence) {
				t.Fatalf("decodeBrowserEnrollmentChoices() error = %v", err)
			}
		})
	}
}
