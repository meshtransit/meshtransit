package mapsession

import (
	"errors"
	"slices"
	"testing"
)

const (
	testProviderWorkspaceID = "01890f00-0000-7000-8000-000000000102"
	testProviderNetworkID   = "01890f00-0000-7000-8000-000000000202"
)

func networkSharingLock(networkID, direction string) string {
	return `{"kind":"network_sharing","params":{"networks":["` + networkID + `"],"direction":"` + direction + `"}}`
}

func externalSharingLock(direction string) string {
	return `{"kind":"external_sharing","params":{"direction":"` + direction +
		`","networks":[],"allowed_workspaces":[]}}`
}

// A share an enforced guardrail of either side blocks leaves the map with
// its peer; any other share stays.
func TestStoreCutsSharesEnforcedGuardrailsBlock(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		alias      bool
		guardrails map[string][]string
		kept       bool
	}{
		{name: "no guardrails", kept: true},
		{name: "provider side locks its Network", guardrails: map[string][]string{
			testWorkspaceID: {networkSharingLock(testProviderNetworkID, "outgoing")}}},
		{name: "consumer side locks its Network", guardrails: map[string][]string{
			testWorkspaceID: {networkSharingLock(testNetworkID, "incoming")}}},
		{name: "a lock on the other direction keeps it", kept: true, guardrails: map[string][]string{
			testWorkspaceID: {networkSharingLock(testProviderNetworkID, "incoming")}}},
		{name: "other Workspace provider forbids sharing out", alias: true, guardrails: map[string][]string{
			testProviderWorkspaceID: {externalSharingLock("outgoing")}}},
		{name: "consumer forbids receiving from outside", alias: true, guardrails: map[string][]string{
			testWorkspaceID: {externalSharingLock("incoming")}}},
		{name: "the consumer's outgoing lock does not apply", alias: true, kept: true, guardrails: map[string][]string{
			testWorkspaceID: {externalSharingLock("outgoing")}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store, _, transaction, _, identity := validStoreFixture(t)
			if test.alias {
				record, _ := aliasRecordFixture(t)
				store.options.EnableDeviceAliases = true
				transaction.aliasRows = &directEdgeRows{values: []string{encodeDirectRecord(t, record)}}
			} else {
				record, _ := directRecordFixture(t)
				transaction.directRows = &directEdgeRows{values: []string{encodeDirectRecord(t, record)}}
			}
			transaction.guardrails = test.guardrails
			snapshot, err := store.Load(t.Context(), identity)
			if err != nil {
				t.Fatal(err)
			}
			kept := snapshot.DirectDeviceProjectionCount() == 1
			// The fixture has one ordinary peer; the share adds its Device.
			wantPeers, wantCuts := 1, uint64(1)
			if test.kept {
				wantPeers, wantCuts = 2, 0
			}
			if kept != test.kept || !transaction.committed || len(snapshot.AuthorizedPeers()) != wantPeers ||
				store.InventoryStats().GuardrailCuts != wantCuts {
				t.Fatalf("share kept = %v (want %v), peers %d, cuts %d", kept, test.kept,
					len(snapshot.AuthorizedPeers()), store.InventoryStats().GuardrailCuts)
			}
			want := []string{testWorkspaceID}
			if test.alias {
				want = []string{testProviderWorkspaceID, testWorkspaceID}
				slices.Sort(want)
			}
			if requested := guardrailRequest(t, transaction); !slices.Equal(requested, want) {
				t.Fatalf("requested Workspaces %v, want %v", requested, want)
			}
		})
	}
}

func guardrailRequest(t *testing.T, transaction *fakeTransaction) []string {
	t.Helper()
	for index, query := range transaction.queries {
		if query == mapShareGuardrailsSQL {
			return transaction.arguments[index][0].([]string)
		}
	}
	t.Fatal("the guardrail reader did not run")
	return nil
}

// A map without shares reads no guardrails.
func TestStoreReadsNoGuardrailsWithoutShares(t *testing.T) {
	t.Parallel()
	store, _, transaction, _, identity := validStoreFixture(t)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(transaction.queries, mapShareGuardrailsSQL) {
		t.Fatal("guardrails read for a map without shares")
	}
}

// Guardrails that cannot be read, or an answer that is not exactly the
// requested Workspaces, fail the map instead of keeping the share.
func TestStoreFailsClosedWithoutShareGuardrails(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		err        error
		answer     string
		guardrails map[string][]string
	}{
		{name: "read failure", err: errors.New("Workspace is unavailable to this Network")},
		{name: "unknown kind", guardrails: map[string][]string{testWorkspaceID: {`{"kind":"posture","params":{}}`}}},
		{name: "malformed params", guardrails: map[string][]string{
			testWorkspaceID: {`{"kind":"network_sharing","params":{"networks":[],"direction":"outgoing"}}`}}},
		{name: "another Workspace", answer: `[{"workspace_id":"` + testProviderWorkspaceID + `","guardrails":[]}]`},
		{name: "a Workspace missing", answer: `[]`},
		{name: "a Workspace twice", answer: `[{"workspace_id":"` + testWorkspaceID + `","guardrails":[]},` +
			`{"workspace_id":"` + testWorkspaceID + `","guardrails":[]}]`},
		{name: "guardrails absent", answer: `[{"workspace_id":"` + testWorkspaceID + `"}]`},
		{name: "unknown field", answer: `[{"workspace_id":"` + testWorkspaceID + `","guardrails":[],"name":"x"}]`},
		{name: "trailing data", answer: `[{"workspace_id":"` + testWorkspaceID + `","guardrails":[]}] []`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store, _, transaction, _, identity := validStoreFixture(t)
			record, _ := directRecordFixture(t)
			transaction.directRows = &directEdgeRows{values: []string{encodeDirectRecord(t, record)}}
			transaction.guardrailErr, transaction.guardrails = test.err, test.guardrails
			transaction.guardrailAnswer = test.answer
			snapshot, err := store.Load(t.Context(), identity)
			if err == nil || snapshot.IsValid() || transaction.committed || transaction.rollbackCalls != 1 {
				t.Fatalf("map kept a share without its guardrails: %v", err)
			}
		})
	}
}
