package postgres

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/node/inventory"
)

const inventoryLifecycleDocument = `{"workspace_id":"01890f00-0000-7000-8000-000000000101",
"network_id":"01890f00-0000-7000-8000-000000000201","inventory_revision":7,
"workspace_code":"000000000101","network_code":"000000000201","devices":[
{"id":"01890f00-0000-7000-8000-000000000901","hostname":"alice-laptop","state":"suspended",
 "is_ephemeral":false,"version":3,"created_at":"2026-10-01T08:00:00Z","updated_at":"2026-10-02T08:00:00Z",
 "expires_at":"2026-11-01T08:00:00Z","ownership":"member",
 "owner":{"principal_id":"01890f00-0000-7000-8000-000000000011","display_name":"Alice"},
 "suspended_reason":"handover",
 "handover_to":{"principal_id":"01890f00-0000-7000-8000-000000000012","display_name":"Bao"},
 "dns_label":"alice-laptop"},
{"id":"01890f00-0000-7000-8000-000000000902","hostname":"db-1","state":"active",
 "is_ephemeral":false,"version":2,"created_at":"2026-10-01T08:00:00Z","updated_at":"2026-10-01T08:00:00Z",
 "expires_at":"2200-01-01T00:00:00Z","ownership":"workspace","owner":null,
 "suspended_reason":null,"handover_to":null,"dns_label":null}]}`

func TestDecodeConsoleDeviceInventoryLifecycle(t *testing.T) {
	t.Parallel()
	result, err := decodeConsoleDeviceInventory(inventoryLifecycleDocument)
	if err != nil || len(result.Devices) != 2 {
		t.Fatalf("decode = %+v, %v", result, err)
	}
	laptop := result.Devices[0].Lifecycle()
	if laptop.Ownership != "member" || laptop.Owner.DisplayName != "Alice" || laptop.SuspendedReason != "handover" ||
		laptop.HandoverTo.DisplayName != "Bao" {
		t.Fatalf("laptop lifecycle = %+v", laptop)
	}
	if server := result.Devices[1].Lifecycle(); server.Ownership != "workspace" || server.Owner.PrincipalID.IsValid() {
		t.Fatalf("server lifecycle = %+v", server)
	}
	if label, ok := result.Devices[0].DNSLabel(); !ok || label.String() != "alice-laptop" {
		t.Fatalf("laptop label = %q, %v", label, ok)
	}
	if _, ok := result.Devices[1].DNSLabel(); ok {
		t.Fatal("a Device without a label decoded one")
	}
	if result.WorkspaceCode != "000000000101" || result.NetworkCode != "000000000201" {
		t.Fatalf("codes = %q %q", result.WorkspaceCode, result.NetworkCode)
	}
	for name, broken := range map[string]string{
		"suspended without reason": strings.Replace(inventoryLifecycleDocument, `"suspended_reason":"handover"`,
			`"suspended_reason":null`, 1),
		"handover without member": strings.Replace(inventoryLifecycleDocument,
			`"handover_to":{"principal_id":"01890f00-0000-7000-8000-000000000012","display_name":"Bao"}`,
			`"handover_to":null`, 1),
		"workspace with owner": strings.Replace(inventoryLifecycleDocument, `"ownership":"workspace","owner":null`,
			`"ownership":"workspace","owner":{"principal_id":"01890f00-0000-7000-8000-000000000011","display_name":"A"}`, 1),
		"unknown ownership": strings.Replace(inventoryLifecycleDocument, `"ownership":"workspace"`,
			`"ownership":"team"`, 1),
		"invalid label": strings.Replace(inventoryLifecycleDocument, `"dns_label":"alice-laptop"`,
			`"dns_label":"Alice_Laptop"`, 1),
		"missing codes": strings.Replace(inventoryLifecycleDocument, `"workspace_code":"000000000101",`, ``, 1),
	} {
		if _, err := decodeConsoleDeviceInventory(broken); !errors.Is(err, inventory.ErrInvalidResult) {
			t.Errorf("%s: error = %v, want ErrInvalidResult", name, err)
		}
	}
}
