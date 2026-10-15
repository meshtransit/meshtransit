package postgres

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
	audit := shareStoreSpec(t, guardrail.ModeAudit)
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
		{name: "switching to audit restores without a hash", changed: 1,
			saved: guardrail.Guardrail{ID: id, Version: 2, Spec: audit},
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationUpdate, Spec: audit,
				ExpectedVersion: 1, Previous: &enforced},
			inventory: shareStoreInventory(t, guardrail.Guardrail{ID: id, Version: 2, Spec: audit})},
		{name: "deleting restores without a hash", changed: 1, deleted: true,
			saved: guardrail.Guardrail{ID: id, Version: 2, Spec: enforced},
			change: guardrail.Change{WorkspaceID: workspaceID, Operation: guardrail.OperationDelete, Spec: enforced,
				ExpectedVersion: 1, Previous: &enforced},
			inventory: shareStoreInventory(t)},
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
			shares, err := checkGuardrailShareImpact(t.Context(), transaction, test.change, test.saved, test.deleted, changeID)
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
	inventory, err := decodeGuardrailShareInventory(encoded)
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
		if _, err := decodeGuardrailShareInventory(encoded); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
