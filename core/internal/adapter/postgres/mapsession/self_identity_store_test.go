package mapsession

import (
	"slices"
	"strings"
	"testing"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

// The account names ride on the snapshot read itself: the reader is joined
// with the session's authenticated keys, no extra round trip.
func TestSnapshotWithIdentitySQLJoinsTheReader(t *testing.T) {
	t.Parallel()
	if loadSnapshotWithIdentitySQL == loadSnapshotSQL ||
		!strings.Contains(loadSnapshotWithIdentitySQL,
			"LEFT JOIN LATERAL mesh_ops.read_map_self_identity_v1($1::BYTEA, $2::BYTEA) AS identity ON TRUE") ||
		!strings.Contains(loadSnapshotWithIdentitySQL, "identity.owner_display_name\nFROM mesh.device AS device") ||
		!strings.HasSuffix(loadSnapshotWithIdentitySQL, "AND device.expires_at > pg_catalog.transaction_timestamp()") {
		t.Fatalf("loadSnapshotWithIdentitySQL = %s", loadSnapshotWithIdentitySQL)
	}
}

// S4b §3.2: the full read carries the Device's account names in the same
// statement, bound to the session's keys.
func TestStoreLoadsSelfIdentity(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	transaction.selfIdentity = &selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice")}
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got := snapshot.SelfIdentity()
	if !got.Known() || got.WorkspaceName() != "Acme" || got.Ownership() != appmapsession.OwnershipMember ||
		got.OwnerName() != "Alice" {
		t.Fatalf("SelfIdentity() = %+v", got)
	}
	read := slices.Index(transaction.queries, loadSnapshotWithIdentitySQL)
	fingerprint := identity.MachineFingerprint()
	nodeKey := identity.NodeKey().Bytes()
	if read < 0 || slices.Contains(transaction.queries, loadSnapshotSQL) {
		t.Fatalf("queries = %v, want the snapshot read with the names", transaction.queries)
	}
	if args := transaction.arguments[read]; len(args) != 2 || string(args[0].([]byte)) != string(fingerprint[:]) ||
		string(args[1].([]byte)) != string(nodeKey[:]) {
		t.Fatalf("snapshot read arguments = %v, want the authenticated keys", args)
	}
}

// Presentation only: no row or names the map cannot carry leave the map
// without them; it still loads.
func TestStoreLoadsWithoutSelfIdentity(t *testing.T) {
	t.Run("no row", func(t *testing.T) {
		store, _, transaction, _, identity := validStoreFixture(t)
		transaction.selfIdentityGranted = true
		snapshot, err := store.Load(t.Context(), identity)
		if err != nil || !snapshot.IsValid() || snapshot.SelfIdentity().Known() ||
			store.InventoryStats().SelfIdentityRejected != 0 {
			t.Fatalf("Load() = %t %+v, %v", snapshot.IsValid(), snapshot.SelfIdentity(), err)
		}
	})
	for name, row := range map[string]selfIdentityRow{
		"unknown ownership": {workspace: "Acme", ownership: "robot"},
		"control character": {workspace: "Ac\u0007me", ownership: "member"},
		"padded name":       {workspace: "Acme", ownership: "member", owner: textPointer(" Alice")},
	} {
		t.Run(name, func(t *testing.T) {
			store, _, transaction, _, identity := validStoreFixture(t)
			transaction.selfIdentity = &row
			snapshot, err := store.Load(t.Context(), identity)
			if err != nil || !snapshot.IsValid() || snapshot.SelfIdentity().Known() {
				t.Fatalf("Load() = %t %+v, %v", snapshot.IsValid(), snapshot.SelfIdentity(), err)
			}
			if store.InventoryStats().SelfIdentityRejected != 1 {
				t.Fatalf("stats = %+v, want one rejected", store.InventoryStats())
			}
		})
	}
	t.Run("not granted", func(t *testing.T) {
		store, _, transaction, _, identity := validStoreFixture(t)
		snapshot, err := store.Load(t.Context(), identity)
		if err != nil || snapshot.SelfIdentity().Known() || slices.Contains(transaction.queries, loadSnapshotWithIdentitySQL) {
			t.Fatalf("Load() = %+v, %v; queries %v", snapshot.SelfIdentity(), err, transaction.queries)
		}
	})
}

// A Workspace's Device carries no person's name, even if one were read.
func TestStoreSelfIdentityOfAWorkspaceDevice(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	transaction.selfIdentity = &selfIdentityRow{workspace: "Acme", ownership: "workspace", owner: textPointer("Alice")}
	snapshot, err := store.Load(t.Context(), identity)
	got := snapshot.SelfIdentity()
	if err != nil || !got.Known() || got.Ownership() != appmapsession.OwnershipWorkspace || got.OwnerName() != "" {
		t.Fatalf("SelfIdentity() = %+v, %v", got, err)
	}
}

// S4b §3.2-§3.3: a rebuild from the shared view keeps the owner's name from
// current and takes the Workspace's from the view; a map whose Workspace
// name the view no longer has is not unchanged.
func TestDeriveCarriesSelfIdentity(t *testing.T) {
	store, transaction, record := liveStoreFixture(t)
	transaction.selfIdentity = &selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice")}
	transaction.workspaceName = textPointer("Acme Labs")
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil || loaded.SelfIdentity().WorkspaceName() != "Acme" {
		t.Fatalf("Load() = %+v, %v", loaded.SelfIdentity(), err)
	}
	derived, found, err := store.Derive(t.Context(), loaded, record.networkRevision)
	if err != nil || !found {
		t.Fatalf("Derive() = %t, %v", found, err)
	}
	got := derived.SelfIdentity()
	if !got.Known() || got.WorkspaceName() != "Acme Labs" || got.OwnerName() != "Alice" ||
		got.Ownership() != appmapsession.OwnershipMember {
		t.Fatalf("derived SelfIdentity() = %+v", got)
	}
	if unchanged, err := store.Unchanged(t.Context(), loaded, record.networkRevision); err != nil || unchanged {
		t.Fatalf("Unchanged(loaded) = %t, %v; want a rebuild for the new Workspace name", unchanged, err)
	}
	if unchanged, err := store.Unchanged(t.Context(), derived, record.networkRevision); err != nil || !unchanged {
		t.Fatalf("Unchanged(derived) = %t, %v; want it current", unchanged, err)
	}
}

// A Workspace name the schema takes but a map cannot carry is left out, so
// it never keeps every map rebuilding.
func TestDeriveIgnoresAWorkspaceNameAMapCannotCarry(t *testing.T) {
	store, transaction, record := liveStoreFixture(t)
	transaction.selfIdentity = &selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice")}
	transaction.workspaceName = textPointer("Acme\t")
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if unchanged, err := store.Unchanged(t.Context(), loaded, record.networkRevision); err != nil || !unchanged {
		t.Fatalf("Unchanged() = %t, %v; want the unusable name ignored", unchanged, err)
	}
}

// The owner's name is carried from current only while the owner is the
// same: a Device whose owner changed is read again.
func TestDeriveRereadsADeviceWhoseOwnerChanged(t *testing.T) {
	store, transaction, record := liveStoreFixture(t)
	transaction.selfIdentity = &selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice")}
	self := &transaction.inventoryRows[0].records[2]
	self.numericOwnerID++
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, found, err := store.Derive(t.Context(), loaded, record.networkRevision); err != nil || found {
		t.Fatalf("Derive() = %t, %v; want a reread", found, err)
	}
}

// S4c §3.2: schema 288's reader is joined the same way as v1's and adds only
// the owner's email.
func TestSnapshotWithIdentityEmailSQLJoinsTheV2Reader(t *testing.T) {
	t.Parallel()
	if !strings.Contains(loadSnapshotWithIdentityEmailSQL,
		"LEFT JOIN LATERAL mesh_ops.read_map_self_identity_v2($1::BYTEA, $2::BYTEA) AS identity ON TRUE") ||
		!strings.Contains(loadSnapshotWithIdentityEmailSQL,
			"identity.owner_display_name,\n    identity.owner_email\nFROM mesh.device AS device") ||
		strings.Contains(loadSnapshotWithIdentityEmailSQL, "read_map_self_identity_v1") ||
		strings.Replace(loadSnapshotWithIdentityEmailSQL, "read_map_self_identity_v2", "read_map_self_identity_v1", 1) ==
			loadSnapshotWithIdentitySQL ||
		!strings.HasSuffix(loadSnapshotWithIdentityEmailSQL, "AND device.expires_at > pg_catalog.transaction_timestamp()") {
		t.Fatalf("loadSnapshotWithIdentityEmailSQL = %s", loadSnapshotWithIdentityEmailSQL)
	}
}

func TestStoreLoadsTheOwnersEmail(t *testing.T) {
	for name, test := range map[string]struct {
		row       selfIdentityRow
		email     string
		rejected  uint64
		ownerName string
	}{
		"member": {
			row:   selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice"), email: textPointer("alice@example.test")},
			email: "alice@example.test", ownerName: "Alice",
		},
		"no email yet": {
			row: selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice")}, ownerName: "Alice",
		},
		"workspace device": {
			row: selfIdentityRow{workspace: "Acme", ownership: "workspace", email: textPointer("alice@example.test")},
		},
		"email a Device may not show": {
			row:      selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice"), email: textPointer("al\u202eice@example.test")},
			rejected: 1, ownerName: "Alice",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, _, transaction, _, identity := validStoreFixture(t)
			transaction.selfIdentityEmailGranted = true
			row := test.row
			transaction.selfIdentity = &row
			snapshot, err := store.Load(t.Context(), identity)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			got := snapshot.SelfIdentity()
			email, read := got.OwnerEmail()
			if !got.Known() || got.OwnerName() != test.ownerName || !read || email != test.email {
				t.Fatalf("SelfIdentity() = %+v", got)
			}
			if stats := store.InventoryStats(); stats.SelfIdentityEmailRejected != test.rejected ||
				stats.SelfIdentityRejected != 0 {
				t.Fatalf("rejected = %+v, want %d emails and no names", stats, test.rejected)
			}
			if !slices.Contains(transaction.queries, loadSnapshotWithIdentityEmailSQL) ||
				slices.Contains(transaction.queries, loadSnapshotWithIdentitySQL) {
				t.Fatalf("queries = %v, want the v2 read", transaction.queries)
			}
		})
	}
}

// A Core on schema 287 keeps the names and sends no email field.
func TestStoreWithoutTheV2ReaderKeepsTheNames(t *testing.T) {
	store, _, transaction, _, identity := validStoreFixture(t)
	transaction.selfIdentity = &selfIdentityRow{workspace: "Acme", ownership: "member", owner: textPointer("Alice")}
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got := snapshot.SelfIdentity()
	if _, read := got.OwnerEmail(); !got.Known() || got.OwnerName() != "Alice" || read {
		t.Fatalf("SelfIdentity() = %+v, want the names without an email", got)
	}
}

func TestDeriveCarriesTheOwnersEmail(t *testing.T) {
	store, transaction, record := liveStoreFixture(t)
	transaction.selfIdentityEmailGranted = true
	transaction.selfIdentity = &selfIdentityRow{
		workspace: "Acme", ownership: "member", owner: textPointer("Alice"), email: textPointer("alice@example.test"),
	}
	transaction.workspaceName = textPointer("Acme")
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	derived, found, err := store.Derive(t.Context(), loaded, record.networkRevision)
	if email, read := derived.SelfIdentity().OwnerEmail(); err != nil || !found || !read ||
		email != "alice@example.test" {
		t.Fatalf("Derive() = %+v %t, %v", derived.SelfIdentity(), found, err)
	}
}
