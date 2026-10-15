package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	shareStoreWorkspace = "01890f00-0000-7000-8000-000000000103"
	shareStorePartner   = "01890f00-0000-7000-8000-000000000102"
	shareStoreNetwork   = "01890f00-0000-7000-8000-000000000203"
	shareStoreReceiver  = "01890f00-0000-7000-8000-000000000202"
	shareStoreContract  = "01890f00-0000-7000-8000-000000000a01"
	shareStoreGuardrail = "01890f00-0000-7000-8000-000000000a02"
)

func shareStoreSpec(t *testing.T, mode guardrail.Mode) guardrail.Spec {
	t.Helper()
	production, err := network.ParseID(shareStoreNetwork)
	if err != nil {
		t.Fatal(err)
	}
	return guardrail.Spec{Kind: guardrail.KindNetworkSharing, Name: "Production shares nothing", Mode: mode,
		Sharing: guardrail.NetworkSharingParams{Networks: []network.ID{production}, Direction: guardrail.DirectionOutgoing}}
}

// shareStoreInventory is the schema 164 document: the guardrails given and
// one share out of production to a partner Workspace.
func shareStoreInventory(t *testing.T, guardrails ...guardrail.Guardrail) string {
	t.Helper()
	documents := make([]map[string]any, len(guardrails))
	for index, item := range guardrails {
		params, err := item.ParamsDocument()
		if err != nil {
			t.Fatal(err)
		}
		documents[index] = map[string]any{"guardrail_id": item.ID.String(), "kind": item.Kind, "name": item.Name,
			"description": item.Description, "mode": item.Mode, "params": json.RawMessage(params),
			"version": item.Version, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}
	}
	encoded, err := json.Marshal(map[string]any{"guardrails": documents, "contracts": []map[string]string{{
		"trust_contract_id": shareStoreContract, "provider_workspace_id": shareStoreWorkspace,
		"provider_network_id": shareStoreNetwork, "consumer_workspace_id": shareStorePartner,
		"consumer_network_id": shareStoreReceiver, "side": "provider", "network_id": shareStoreNetwork,
		"label": "db",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestCheckGuardrailShareImpact(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID(shareStoreWorkspace)
	id, _ := publicid.Parse(shareStoreGuardrail)
	changeID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a03")
	enforced := shareStoreSpec(t, guardrail.ModeEnforce)
	preview, err := guardrail.ComputeImpact(workspaceID, nil, guardrail.Candidate{Spec: enforced},
		mustInventory(t, shareStoreInventory(t)).Contracts)
	if err != nil || len(preview.Affected) != 1 {
		t.Fatalf("preview = %+v, %v", preview, err)
	}
	saved := guardrail.Guardrail{ID: id, Version: 1, Spec: enforced}
	for _, test := range []struct {
		name      string
		change    guardrail.Change
		saved     guardrail.Guardrail
		deleted   bool
		inventory string
		changed   int
		err       error
	}{
		{name: "create with the preview's hash cuts the share", saved: saved, changed: 1,
			change:    guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationCreate, Spec: enforced, ImpactHash: preview.Hash},
			inventory: shareStoreInventory(t, saved)},
		{name: "create without a hash", saved: saved, err: guardrail.ErrImpactChanged,
			change:    guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationCreate, Spec: enforced},
			inventory: shareStoreInventory(t, saved)},
		{name: "create with another impact's hash", saved: saved, err: guardrail.ErrImpactChanged,
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationCreate, Spec: enforced,
				ImpactHash: guardrail.ImpactHash{1}},
			inventory: shareStoreInventory(t, saved)},
		{name: "a read without the saved guardrail", saved: saved, err: guardrail.ErrUnavailable,
			change:    guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationCreate, Spec: enforced, ImpactHash: preview.Hash},
			inventory: shareStoreInventory(t)},
		{name: "a malformed read", saved: saved, err: guardrail.ErrUnavailable,
			change:    guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationCreate, Spec: enforced, ImpactHash: preview.Hash},
			inventory: strings.Replace(shareStoreInventory(t, saved), `"provider"`, `"owner"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{test.inventory}}}
			shares, err := checkGuardrailShareImpact(t.Context(), transaction, test.change, test.saved, test.deleted, changeID,
				guardrail.MaximumShareContracts)
			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Fatalf("error = %v, want %v", err, test.err)
				}
				return
			}
			if err != nil || len(shares.changed) != test.changed {
				t.Fatalf("changed %d shares (%v), want %d", len(shares.changed), err, test.changed)
			}
		})
	}
}

func mustInventory(t *testing.T, encoded string) guardrail.ShareInventory {
	t.Helper()
	inventory, err := decodeGuardrailShareInventory(encoded, guardrail.MaximumShareContracts)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func TestDecodeGuardrailShareInventoryIsStrict(t *testing.T) {
	t.Parallel()
	valid := shareStoreInventory(t)
	if inventory := mustInventory(t, valid); len(inventory.Contracts) != 1 || inventory.Contracts[0].Label != "db" {
		t.Fatalf("inventory = %+v", inventory)
	}
	for name, encoded := range map[string]string{
		"unknown field":   strings.Replace(valid, `"label"`, `"extra":"x","label"`, 1),
		"no contracts":    `{"guardrails":[]}`,
		"bad contract id": strings.Replace(valid, shareStoreContract, "x", 1),
		"long label":      strings.Replace(valid, `"label":"db"`, `"label":"`+strings.Repeat("x", 129)+`"`, 1),
		"trailing data":   valid + "{}",
		"foreign Network": strings.Replace(valid, `"network_id":"`+shareStoreNetwork, `"network_id":"x`, 1),
		"guardrails null": strings.Replace(valid, `"guardrails":[]`, `"guardrails":null`, 1),
	} {
		if _, err := decodeGuardrailShareInventory(encoded, guardrail.MaximumShareContracts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Only a result in enforce mode reads shares, under the impact bound. A
// deletion or switch to audit of an enforced guardrail asks PostgreSQL to
// wake the Networks the guardrail named, without a share list; any other
// change reads nothing.
func TestGuardrailChangeSharesDispatch(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID(shareStoreWorkspace)
	id, _ := publicid.Parse(shareStoreGuardrail)
	changeID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a03")
	enforced, audit := shareStoreSpec(t, guardrail.ModeEnforce), shareStoreSpec(t, guardrail.ModeAudit)
	store := &GuardrailStore{limits: GuardrailShareLimits{Impact: 7, WakeNetworks: 3}}
	for _, test := range []struct {
		name    string
		change  guardrail.Change
		saved   guardrail.Guardrail
		deleted bool
		query   string
		limit   int
	}{
		{name: "enforce create reads shares", query: guardrailChangeShareContractsSQL, limit: 7,
			saved:  guardrail.Guardrail{ID: id, Version: 1, Spec: enforced},
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationCreate, Spec: enforced}},
		{name: "switch to audit wakes", query: wakeGuardrailShareNetworksSQL, limit: 3,
			saved: guardrail.Guardrail{ID: id, Version: 2, Spec: audit},
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationUpdate, Spec: audit,
				ExpectedVersion: 1, Previous: &enforced}},
		{name: "delete wakes", query: wakeGuardrailShareNetworksSQL, limit: 3, deleted: true,
			saved: guardrail.Guardrail{ID: id, Version: 2, Spec: enforced},
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationDelete, Spec: enforced,
				ExpectedVersion: 1, Previous: &enforced}},
		{name: "an audit edit changes no map", saved: guardrail.Guardrail{ID: id, Version: 2, Spec: audit},
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationUpdate, Spec: audit,
				ExpectedVersion: 1, Previous: &audit}},
		{name: "deleting an audit guardrail changes no map", deleted: true,
			saved: guardrail.Guardrail{ID: id, Version: 2, Spec: audit},
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationDelete, Spec: audit,
				ExpectedVersion: 1, Previous: &audit}},
	} {
		transaction := &recordingGuardrailTransaction{err: errors.New("stop")}
		_, _ = store.changeShares(t.Context(), transaction, test.change, test.saved, test.deleted, changeID)
		switch {
		case test.query == "" && len(transaction.queries) != 0:
			t.Errorf("%s: read %v", test.name, transaction.queries)
		case test.query != "" && (len(transaction.queries) != 1 || transaction.queries[0] != test.query):
			t.Errorf("%s: read %v, want %s", test.name, transaction.queries, test.query)
		case test.query == wakeGuardrailShareNetworksSQL:
			networks, _ := transaction.arguments[0][1].([]string)
			if len(networks) != 1 || networks[0] != shareStoreNetwork || transaction.arguments[0][2] != test.limit {
				t.Errorf("%s: wakeup arguments %v", test.name, transaction.arguments[0])
			}
		case test.query != "" && transaction.arguments[0][1] != test.limit:
			t.Errorf("%s: read limit %v, want %d", test.name, transaction.arguments[0][1], test.limit)
		}
	}
}

// The wakeup answer is trusted only within its bound.
func TestWakeGuardrailShareNetworksBounds(t *testing.T) {
	t.Parallel()
	changeID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a03")
	head := `{"workspace_id":"` + shareStoreWorkspace + `","network_id":"` + shareStoreNetwork +
		`","own_workspace":true,"network_revision":2,"sharing_revision":2,"stream_id":1,"next_sequence":1,` +
		`"latest_event_hash":"` + strings.Repeat("00", 32) + `"}`
	for _, test := range []struct {
		name, answer string
		valid        bool
		deferred     bool
	}{
		{name: "none", answer: `{"heads":[],"deferred":false}`, valid: true},
		{name: "one", answer: `{"heads":[` + head + `],"deferred":false}`, valid: true},
		{name: "one deferred at a bound of one", answer: `{"heads":[` + head + `],"deferred":true}`, valid: true,
			deferred: true},
		{name: "deferred below the bound", answer: `{"heads":[],"deferred":true}`},
		{name: "over the bound", answer: `{"heads":[` + head + `,` + head + `],"deferred":false}`},
		{name: "no heads", answer: `{"deferred":false}`},
	} {
		transaction := &recordingGuardrailTransaction{answer: test.answer}
		outcome, err := wakeGuardrailShareNetworks(t.Context(), transaction,
			shareStoreSpec(t, guardrail.ModeEnforce), changeID, 1)
		if (err == nil) != test.valid || outcome.deferred != test.deferred {
			t.Errorf("%s: %+v, %v", test.name, outcome, err)
		}
	}
}

// recordingGuardrailTransaction records each query and answers it with
// answer, or fails with err.
type recordingGuardrailTransaction struct {
	queries   []string
	arguments [][]any
	answer    string
	err       error
}

func (*recordingGuardrailTransaction) Exec(context.Context, string, ...any) error { return nil }

func (transaction *recordingGuardrailTransaction) QueryRow(_ context.Context, query string,
	arguments ...any) accountSessionRow {
	transaction.queries = append(transaction.queries, query)
	transaction.arguments = append(transaction.arguments, arguments)
	if transaction.err != nil {
		return fakeAccountSessionRow{err: transaction.err}
	}
	return fakeAccountSessionRow{values: []any{transaction.answer}}
}

func (*recordingGuardrailTransaction) Commit(context.Context) error   { return nil }
func (*recordingGuardrailTransaction) Rollback(context.Context) error { return nil }

// The bump always runs with every share evaluated, so PostgreSQL can refuse
// the change when a share appeared or ended meanwhile; that refusal is a
// retryable conflict.
func TestBumpGuardrailShareNetworksRechecks(t *testing.T) {
	t.Parallel()
	changeID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a03")
	inventory := mustInventory(t, shareStoreInventory(t))
	transaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{"[]"}}}
	heads, err := bumpGuardrailShareNetworks(t.Context(), transaction,
		guardrailShareChange{contracts: inventory.Contracts, changed: []guardrail.ShareContract{}}, changeID)
	if err != nil || len(heads) != 0 {
		t.Fatalf("nothing changed: heads %v, %v", heads, err)
	}
	evaluated, ok := transaction.arguments[1].([]string)
	if changed, _ := transaction.arguments[0].([]string); !ok || len(changed) != 0 || len(evaluated) != 1 ||
		evaluated[0] != shareStoreContract {
		t.Fatalf("bump arguments = %v", transaction.arguments)
	}
	stale := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{err: &pgconn.PgError{Code: "40001"}}}
	if _, err := bumpGuardrailShareNetworks(t.Context(), stale,
		guardrailShareChange{contracts: inventory.Contracts, changed: inventory.Contracts}, changeID); !errors.Is(err,
		guardrail.ErrVersionConflict) {
		t.Fatalf("a share made meanwhile: %v", err)
	}
	// Heads for a change that changed nothing, or none for one that did, are
	// not trusted.
	odd := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{`[{"stream_id":1}]`}}}
	if _, err := bumpGuardrailShareNetworks(t.Context(), odd,
		guardrailShareChange{contracts: inventory.Contracts}, changeID); !errors.Is(err, guardrail.ErrUnavailable) {
		t.Errorf("heads for nothing: %v", err)
	}
	none := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{"[]"}}}
	if _, err := bumpGuardrailShareNetworks(t.Context(), none,
		guardrailShareChange{contracts: inventory.Contracts, changed: inventory.Contracts}, changeID); !errors.Is(err,
		guardrail.ErrUnavailable) {
		t.Errorf("no heads for a change: %v", err)
	}
}
