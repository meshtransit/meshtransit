package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
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
			file == "flowlog_directory_store.go" || file == "flowlog_status_store.go" {
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
		AliasCount: 1,
		Aliases: &[]flowlogContractAlias{{
			Contract: "01890f00-0000-7000-8000-000000000070", Address: "100.127.0.9",
		}},
	}
	directory, err := newReceiverDirectory(head)
	if err != nil || directory.Revision != 3 || len(directory.Sites[0].Routers) != 1 ||
		len(directory.ExitPools[0].Candidates) != 1 || directory.AliasPrefixes[0].Bits() != 16 ||
		len(directory.ContractAliases) != 1 || directory.ContractAliases[0].Address.String() != "100.127.0.9" {
		t.Fatalf("directory = %+v, %v", directory, err)
	}
	for name, change := range map[string]func(*flowlogDirectoryNetworkRow){
		"unmasked prefix":  func(row *flowlogDirectoryNetworkRow) { row.MeshPrefixes = []string{"100.64.0.1/10"} },
		"alias prefix":     func(row *flowlogDirectoryNetworkRow) { row.AliasPrefixes = []string{"nope"} },
		"site":             func(row *flowlogDirectoryNetworkRow) { row.Sites[0].ID = "x" },
		"router":           func(row *flowlogDirectoryNetworkRow) { row.Sites[0].Routers = []string{"x"} },
		"tag":              func(row *flowlogDirectoryNetworkRow) { row.Tags = []flowlogDirectoryName{{ID: "x", Name: "a"}} },
		"alias count":      func(row *flowlogDirectoryNetworkRow) { row.AliasCount = 2 },
		"aliases withheld": func(row *flowlogDirectoryNetworkRow) { row.Aliases = nil },
		"alias address": func(row *flowlogDirectoryNetworkRow) {
			row.Aliases = &[]flowlogContractAlias{{Contract: "01890f00-0000-7000-8000-000000000070", Address: "x"}}
		},
		"alias contract": func(row *flowlogDirectoryNetworkRow) {
			row.Aliases = &[]flowlogContractAlias{{Contract: "x", Address: "100.127.0.9"}}
		},
	} {
		row := head
		row.Sites = []flowlogDirectorySite{head.Sites[0]}
		change(&row)
		if _, err := newReceiverDirectory(row); !errors.Is(err, ErrFlowlogReceiver) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A report's entries go to the database as the function reads them: tags
// in hex, no time as null, counts clamped.
func TestFlowlogStatusEntries(t *testing.T) {
	t.Parallel()
	workspaceID := workspace.ID(must(publicid.Parse("01890f00-0000-7000-8000-000000000001")))
	networkID := network.ID(must(publicid.Parse("01890f00-0000-7000-8000-000000000002")))
	at := time.Unix(1_900_000_000, 0)
	encoded, err := flowlogStatusEntries([]connectionlog.ReceiverNetworkStatus{
		{Workspace: workspaceID, Network: networkID, TestedETag: bytes.Repeat([]byte{0xab}, 16), TestResult: "ok",
			TestedAt: at, DeliveryError: "none", Lost: math.MaxUint64},
		{Workspace: workspaceID, Network: networkID, TestResult: "unspecified", DeliveryError: "unspecified"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(encoded, &entries); err != nil {
		t.Fatal(err)
	}
	if entries[0]["tested_etag"] != strings.Repeat("ab", 16) || entries[0]["delivered_at"] != nil ||
		entries[0]["lost"] != float64(math.MaxInt64) || entries[1]["tested_etag"] != nil ||
		entries[1]["tested_at"] != nil || entries[0]["network"] != networkID.String() {
		t.Fatalf("entries = %s", encoded)
	}
	if _, err := flowlogStatusEntries([]connectionlog.ReceiverNetworkStatus{{TestedETag: []byte{1}}}); err == nil {
		t.Fatal("a short tag was encoded")
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
