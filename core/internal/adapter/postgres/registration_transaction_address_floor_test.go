package postgres

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/ipam"
)

func floorRow(floor, prefix string) registrationTestRow {
	return registrationTestRow{scan: func(destinations ...any) error {
		*destinations[0].(*string) = floor
		*destinations[1].(*string) = prefix
		return nil
	}}
}

func liveLeaseRow(address string, unsettled bool) func(...any) error {
	return func(destinations ...any) error {
		*destinations[0].(*int64) = 501
		*destinations[1].(*int64) = 700
		*destinations[2].(*string) = address
		*destinations[3].(*int) = 4
		*destinations[4].(*string) = "primary"
		*destinations[5].(*string) = "active"
		*destinations[6].(*bool) = unsettled
		return nil
	}
}

func liveLeaseWindow(from netip.Addr, count int) *registrationTestRows {
	rows := &registrationTestRows{}
	for range count {
		rows.scans = append(rows.scans, liveLeaseRow(from.String(), false))
		from = from.Next()
	}
	return rows
}

// registerWithFloor resolves and applies one registration whose IPv4 prefix
// 100.64.1.0/24 has the given floor row, after configure adjusts the queued
// reads, and returns the database calls.
func registerWithFloor(
	t *testing.T,
	floor registrationTestRow,
	configure func(*fakeRegistrationDatabaseTransaction),
) ([]registrationTestCall, error) {
	t.Helper()
	command := validRegistrationReplayCommand(t)
	database := newFakeRegistrationDatabaseTransaction()
	enqueueOpenRegistrationResolution(t, database, command)
	database.rows[lockRegistrationAddressFloorSQL][0] = floor
	if configure != nil {
		configure(database)
	}
	enqueueRegistrationWrites(database)
	transaction := beginTestRegistrationTransaction(t, database, command)
	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		return database.calls, err
	}
	_, err = transaction.Apply(t.Context(), testRegistrationChange(t, command, resolution))
	return database.calls, err
}

func leasedAddress(t *testing.T, calls []registrationTestCall) any {
	t.Helper()
	return findRegistrationCall(t, calls, insertRegistrationLeaseSQL).arguments[7]
}

func storedFloor(t *testing.T, calls []registrationTestCall) any {
	t.Helper()
	return findRegistrationCall(t, calls, storeRegistrationAddressFloorSQL).arguments[1]
}

func countCalls(calls []registrationTestCall, query string) int {
	count := 0
	for _, call := range calls {
		if call.query == query {
			count++
		}
	}
	return count
}

func TestRegistrationAllocatesFromTheAddressFloor(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		floor       registrationTestRow
		configure   func(*fakeRegistrationDatabaseTransaction)
		wantAddress string
		wantFloor   string
		wantWindows int
	}{
		{
			name:  "free floor",
			floor: floorRow("100.64.1.200", "100.64.1.0/24"),
			configure: func(database *fakeRegistrationDatabaseTransaction) {
				database.enqueueRow(lowestReclaimableRegistrationAddressSQL, registrationTestRow{err: pgx.ErrNoRows})
			},
			wantAddress: "100.64.1.200", wantFloor: "100.64.1.201/32", wantWindows: 1,
		},
		{
			// The release of the reclaimed lease lowers the floor to it;
			// the stored floor puts it back.
			name:  "quarantine ended below the floor",
			floor: floorRow("100.64.1.200", "100.64.1.0/24"),
			configure: func(database *fakeRegistrationDatabaseTransaction) {
				database.enqueueRow(lowestReclaimableRegistrationAddressSQL, registrationTestRow{
					scan: func(destinations ...any) error {
						*destinations[0].(*string) = "100.64.1.7"
						return nil
					},
				})
			},
			wantAddress: "100.64.1.7", wantFloor: "100.64.1.200/32", wantWindows: 0,
		},
		{
			name:  "live leases from the floor",
			floor: floorRow("100.64.1.10", "100.64.1.0/24"),
			configure: func(database *fakeRegistrationDatabaseTransaction) {
				database.enqueueRow(lowestReclaimableRegistrationAddressSQL, registrationTestRow{err: pgx.ErrNoRows})
				database.rowSets[loadRegistrationLeasesSQL][0] = &registrationTestRows{scans: []func(...any) error{
					liveLeaseRow("100.64.1.10", false),
					liveLeaseRow("100.64.1.11", false),
					liveLeaseRow("100.64.1.13", false),
				}}
			},
			wantAddress: "100.64.1.12", wantFloor: "100.64.1.13/32", wantWindows: 1,
		},
		{
			name:  "unsettled lease stops the floor",
			floor: floorRow("100.64.1.10", "100.64.1.0/24"),
			configure: func(database *fakeRegistrationDatabaseTransaction) {
				database.enqueueRow(lowestReclaimableRegistrationAddressSQL, registrationTestRow{err: pgx.ErrNoRows})
				database.rowSets[loadRegistrationLeasesSQL][0] = &registrationTestRows{scans: []func(...any) error{
					liveLeaseRow("100.64.1.10", false),
					liveLeaseRow("100.64.1.11", true),
				}}
			},
			wantAddress: "100.64.1.12", wantFloor: "100.64.1.11/32", wantWindows: 1,
		},
		{
			name:  "floor of another prefix value",
			floor: floorRow("100.64.1.200", "100.64.0.0/16"),
			configure: func(database *fakeRegistrationDatabaseTransaction) {
				database.rowSets[loadRegistrationLeasesSQL][0] = &registrationTestRows{scans: []func(...any) error{
					liveLeaseRow("100.64.1.1", false),
				}}
			},
			wantAddress: "100.64.1.2", wantFloor: "100.64.1.3/32", wantWindows: 1,
		},
		{
			name:  "full windows",
			floor: floorRow("100.64.1.1", "100.64.1.0/24"),
			configure: func(database *fakeRegistrationDatabaseTransaction) {
				database.rowSets[loadRegistrationLeasesSQL][0] = liveLeaseWindow(netip.MustParseAddr("100.64.1.1"), 200)
			},
			wantAddress: "100.64.1.201", wantFloor: "100.64.1.202/32", wantWindows: 1,
		},
		{
			name:  "missing floor",
			floor: registrationTestRow{err: pgx.ErrNoRows},
			configure: func(database *fakeRegistrationDatabaseTransaction) {
				database.enqueueRow(lockRegistrationAddressFloorSQL, floorRow("100.64.1.1", "100.64.1.0/24"))
			},
			wantAddress: "100.64.1.1", wantFloor: "100.64.1.2/32", wantWindows: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			calls, err := registerWithFloor(t, test.floor, test.configure)
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			if got := leasedAddress(t, calls); got != test.wantAddress {
				t.Errorf("leased %v, want %s", got, test.wantAddress)
			}
			if got := storedFloor(t, calls); got != test.wantFloor {
				t.Errorf("stored floor %v, want %s", got, test.wantFloor)
			}
			if got := countCalls(calls, loadRegistrationLeasesSQL); got != test.wantWindows {
				t.Errorf("read %d lease windows, want %d", got, test.wantWindows)
			}
		})
	}
}

func TestRegistrationAddressFloorArguments(t *testing.T) {
	t.Parallel()
	calls, err := registerWithFloor(t, registrationTestRow{err: pgx.ErrNoRows},
		func(database *fakeRegistrationDatabaseTransaction) {
			database.enqueueRow(lockRegistrationAddressFloorSQL, floorRow("100.64.1.9", "100.64.1.0/24"))
			database.enqueueRow(lowestReclaimableRegistrationAddressSQL, registrationTestRow{err: pgx.ErrNoRows})
		})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	insert := findRegistrationCall(t, calls, insertRegistrationAddressFloorSQL)
	if !reflect.DeepEqual(insert.arguments, []any{int64(101), int64(201), int64(501), "100.64.1.0/24", "100.64.1.1/32"}) {
		t.Errorf("floor insert arguments = %#v, want the first host", insert.arguments)
	}
	reclaim := findRegistrationCall(t, calls, lowestReclaimableRegistrationAddressSQL)
	if !reflect.DeepEqual(reclaim.arguments, []any{int64(501), "100.64.1.1/32", "100.64.1.9/32"}) {
		t.Errorf("reclaim arguments = %#v, want [first host, floor)", reclaim.arguments)
	}
	window := findRegistrationCall(t, calls, loadRegistrationLeasesSQL)
	if !reflect.DeepEqual(window.arguments, []any{int64(501), 256, "100.64.1.9/32"}) {
		t.Errorf("window arguments = %#v, want the floor", window.arguments)
	}
}

// Leases on every host up to the broadcast address exhaust the prefix.
func TestRegistrationWalkEndsAtTheBroadcastAddress(t *testing.T) {
	t.Parallel()
	calls, err := registerWithFloor(t, floorRow("100.64.1.1", "100.64.1.0/24"),
		func(database *fakeRegistrationDatabaseTransaction) {
			database.rowSets[loadRegistrationLeasesSQL][0] = liveLeaseWindow(netip.MustParseAddr("100.64.1.1"), 254)
		})
	if !errors.Is(err, ipam.ErrAddressExhausted) {
		t.Fatalf("register: %v, want the /24 exhausted", err)
	}
	if got := countCalls(calls, loadRegistrationLeasesSQL); got != 1 {
		t.Fatalf("read %d windows; the window ending at the broadcast address ends the walk", got)
	}
}

func TestRegistrationReadsTheNextLeaseWindow(t *testing.T) {
	t.Parallel()
	command := validRegistrationReplayCommand(t)
	database := newFakeRegistrationDatabaseTransaction()
	enqueueOpenRegistrationResolution(t, database, command)
	database.rowSets[lockRegistrationPrefixesSQL][0] = &registrationTestRows{scans: []func(...any) error{
		func(destinations ...any) error {
			*destinations[0].(*int64) = 501
			*destinations[1].(*int64) = 301
			*destinations[2].(*int64) = 401
			*destinations[3].(*string) = "100.64.0.0/16"
			*destinations[4].(*int) = 4
			return nil
		},
	}}
	database.rows[lockRegistrationAddressFloorSQL][0] = floorRow("100.64.0.1", "100.64.0.0/16")
	database.rowSets[loadRegistrationLeasesSQL][0] = liveLeaseWindow(netip.MustParseAddr("100.64.0.1"), 256)
	database.enqueueRows(loadRegistrationLeasesSQL, liveLeaseWindow(netip.MustParseAddr("100.64.1.1"), 3))
	enqueueRegistrationWrites(database)
	transaction := beginTestRegistrationTransaction(t, database, command)
	resolution, err := transaction.Resolve(t.Context(), command)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if _, err := transaction.Apply(t.Context(), testRegistrationChange(t, command, resolution)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	windows := 0
	for _, call := range database.calls {
		if call.query != loadRegistrationLeasesSQL {
			continue
		}
		windows++
		if windows == 2 && call.arguments[2] != "100.64.1.1/32" {
			t.Fatalf("second window starts at %v, want after the first", call.arguments[2])
		}
	}
	if windows != 2 || leasedAddress(t, database.calls) != "100.64.1.4" ||
		storedFloor(t, database.calls) != "100.64.1.5/32" {
		t.Fatalf("windows=%d leased=%v floor=%v", windows, leasedAddress(t, database.calls),
			storedFloor(t, database.calls))
	}
}
