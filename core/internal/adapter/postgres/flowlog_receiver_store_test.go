package postgres

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only the receiver store calls the receiver's cross-tenant reads (design
// C39): no other path of the runtime role may reach them.
func TestOnlyTheReceiverStoreCallsItsReads(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || file == "flowlog_receiver_store.go" ||
			file == "flowlog_directory_store.go" {
			continue
		}
		content, err := os.ReadFile(file) //nolint:gosec // a source file of this package, from Glob
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), "mesh_ops.flowlog_") {
			t.Errorf("%s calls a connection log receiver read", file)
		}
	}
}

func TestNewFlowlogReceiverStoreNeedsTheRuntimePool(t *testing.T) {
	t.Parallel()
	if _, err := NewFlowlogReceiverStore(nil, nil); err == nil {
		t.Fatal("built without a pool")
	}
	if _, err := NewFlowlogReceiverStore(&Pool{role: PoolRoleWorker}, nil); err == nil {
		t.Fatal("built on the worker pool")
	}
}

// A directory's Devices index the dictionaries; anything the schema never
// answers is a broken read, never a partial directory.
func TestReceiverDevices(t *testing.T) {
	t.Parallel()
	tags := []flowlogDirectoryName{{ID: "01890f00-0000-7000-8000-000000000040", Name: "prod"}}
	groups := []flowlogDirectoryName{
		{ID: "01890f00-0000-7000-8000-000000000041", Name: "ops"},
		{ID: "01890f00-0000-7000-8000-000000000042", Name: "dev"},
	}
	pseudonym := "6f1c2a4e-9b3d-4c5e-8f7a-0123456789ab"
	good := flowlogDirectoryDeviceRow{
		ID: "01890f00-0000-7000-8000-000000000010", Kind: "standard", State: "expired", Hostname: "laptop",
		OwnerKind: "member", Pseudonym: &pseudonym, Addresses: []string{"100.64.0.1", "fd7a:115c:a1e0::1"},
		Tags: []string{tags[0].ID}, Groups: []string{groups[1].ID, groups[0].ID},
	}
	devices, err := receiverDevices([]flowlogDirectoryDeviceRow{good}, tags, groups)
	if err != nil || len(devices) != 1 || devices[0].Pseudonym[0] != 0x6f || len(devices[0].Addresses) != 2 ||
		devices[0].Tags[0] != 0 || devices[0].Groups[0] != 1 || devices[0].Groups[1] != 0 {
		t.Fatalf("devices = %+v, %v", devices, err)
	}
	bad := func(change func(*flowlogDirectoryDeviceRow)) flowlogDirectoryDeviceRow {
		row := good
		change(&row)
		return row
	}
	upper, zero := "6F1C2A4E-9B3D-4C5E-8F7A-0123456789AB", "00000000-0000-0000-0000-000000000000"
	for name, row := range map[string]flowlogDirectoryDeviceRow{
		"kind":       bad(func(row *flowlogDirectoryDeviceRow) { row.Kind = "phone" }),
		"state":      bad(func(row *flowlogDirectoryDeviceRow) { row.State = "pending" }),
		"owner kind": bad(func(row *flowlogDirectoryDeviceRow) { row.OwnerKind = "team" }),
		"id":         bad(func(row *flowlogDirectoryDeviceRow) { row.ID = "nope" }),
		"address":    bad(func(row *flowlogDirectoryDeviceRow) { row.Addresses = []string{"100.64.0.0/10"} }),
		"tag":        bad(func(row *flowlogDirectoryDeviceRow) { row.Tags = []string{groups[0].ID} }),
		"group":      bad(func(row *flowlogDirectoryDeviceRow) { row.Groups = []string{tags[0].ID} }),
		"pseudonym":  bad(func(row *flowlogDirectoryDeviceRow) { row.Pseudonym = &upper }),
		"zero":       bad(func(row *flowlogDirectoryDeviceRow) { row.Pseudonym = &zero }),
		"many tags": bad(func(row *flowlogDirectoryDeviceRow) {
			row.Tags = make([]string, 65)
			for index := range row.Tags {
				row.Tags[index] = tags[0].ID
			}
		}),
	} {
		if _, err := receiverDevices([]flowlogDirectoryDeviceRow{row}, tags, groups); !errors.Is(err, ErrFlowlogReceiver) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewReceiverDirectoryRefusesWhatTheSchemaNeverAnswers(t *testing.T) {
	t.Parallel()
	head := flowlogDirectoryNetworkRow{
		Revision: 3, MeshPrefixes: []string{"100.64.0.0/10"}, AliasPrefixes: []string{"100.127.0.0/16"},
		Sites: []flowlogDirectorySite{{
			ID: "01890f00-0000-7000-8000-000000000050", Prefixes: []string{"10.0.0.0/24"},
			Routers: []string{"01890f00-0000-7000-8000-000000000010"},
		}},
		ExitPools: []flowlogDirectoryPool{{
			ID: "01890f00-0000-7000-8000-000000000060", Candidates: []string{"01890f00-0000-7000-8000-000000000010"},
		}},
	}
	directory, err := newReceiverDirectory(head)
	if err != nil || directory.Revision != 3 || len(directory.Sites[0].Routers) != 1 ||
		len(directory.ExitPools[0].Candidates) != 1 || directory.AliasPrefixes[0].Bits() != 16 {
		t.Fatalf("directory = %+v, %v", directory, err)
	}
	for name, change := range map[string]func(*flowlogDirectoryNetworkRow){
		"unmasked prefix": func(row *flowlogDirectoryNetworkRow) { row.MeshPrefixes = []string{"100.64.0.1/10"} },
		"alias prefix":    func(row *flowlogDirectoryNetworkRow) { row.AliasPrefixes = []string{"nope"} },
		"site":            func(row *flowlogDirectoryNetworkRow) { row.Sites[0].ID = "x" },
		"router":          func(row *flowlogDirectoryNetworkRow) { row.Sites[0].Routers = []string{"x"} },
		"tag":             func(row *flowlogDirectoryNetworkRow) { row.Tags = []flowlogDirectoryName{{ID: "x", Name: "a"}} },
	} {
		row := head
		row.Sites = []flowlogDirectorySite{head.Sites[0]}
		change(&row)
		if _, err := newReceiverDirectory(row); !errors.Is(err, ErrFlowlogReceiver) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
