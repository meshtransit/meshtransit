package mapsession

import (
	"context"
	"errors"
	"testing"

	appmapsession "github.com/meshtransit/meshtransit/core/internal/control/mapsession"
)

type aliasVersionDatabase struct{ *fakeDatabase }

func (database *aliasVersionDatabase) BeginWrite(context.Context) (databaseTransaction, error) {
	database.beginCalls++
	if database.transaction == nil {
		return nil, database.err
	}
	return database.transaction, database.err
}

type aliasVersionRow struct{ accepted bool }

func (row aliasVersionRow) Scan(destinations ...any) error {
	*destinations[0].(*bool) = row.accepted
	return nil
}

func TestObserveDeviceAliasVersionBindsIdentityAndJoinsCleanupFailures(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                                string
		accepted, suspended                 bool
		commitError, errorRow, cleanupError bool
	}{
		{name: "accepted", accepted: true}, {name: "foreign identity"}, {name: "suspended", suspended: true},
		{name: "read failure", errorRow: true},
		{name: "unknown commit", accepted: true, commitError: true}, {name: "joined rollback", errorRow: true, cleanupError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store, database, transaction, observer, identity := validStoreFixture(t)
			store.options.EnableDeviceAliases = true
			store.database = &aliasVersionDatabase{fakeDatabase: database}
			failure := errors.New("controlled write failure")
			cleanup := errors.New("controlled cleanup failure")
			transaction.rows = []databaseRow{
				aliasVersionRow{accepted: test.accepted},
				suspendedRow{suspended: test.suspended},
			}
			if test.errorRow {
				transaction.rows = []databaseRow{errorRow{err: failure}}
			}
			if test.commitError {
				transaction.commitErr = failure
			}
			if test.cleanupError {
				transaction.rollbackErr = cleanup
			}
			err := store.ObserveDeviceAliasVersion(t.Context(), identity, 1)
			success := test.accepted && !test.commitError && !test.errorRow
			if (err == nil) != success || transaction.committed != success || observer.operation != OperationObserveClientVersion {
				t.Fatalf("accepted=%t committed=%t error=%v", success, transaction.committed, err)
			}
			if !success && transaction.rollbackCalls != 1 {
				t.Fatal("write transaction leaked")
			}
			if test.cleanupError && (!errors.Is(err, failure) || !errors.Is(err, cleanup)) {
				t.Fatal("cleanup failure discarded")
			}
			if !test.accepted && !test.errorRow && !test.suspended && !errors.Is(err, appmapsession.ErrUnauthorized) {
				t.Fatal("identity denial misclassified")
			}
			if test.suspended && (!errors.Is(err, appmapsession.ErrSuspended) || errors.Is(err, appmapsession.ErrUnauthorized)) {
				t.Fatalf("suspension misclassified: %v", err)
			}
			args := transaction.arguments[1]
			machine, key := identity.MachineFingerprint(), identity.NodeKey().Bytes()
			if string(args[0].([]byte)) != string(machine[:]) || string(args[1].([]byte)) != string(key[:]) || args[2].(int) != 1 {
				t.Fatal("observation not bound to transport identity")
			}
		})
	}
}

func TestObserveDeviceAliasVersionDisabledOrCanceledStartsNoWrite(t *testing.T) {
	t.Parallel()
	store, database, _, _, identity := validStoreFixture(t)
	if err := store.ObserveDeviceAliasVersion(t.Context(), identity, 1); err != nil || database.beginCalls != 0 {
		t.Fatal("disabled compatibility observation performs I/O")
	}
	store.options.EnableDeviceAliases = true
	store.database = &aliasVersionDatabase{fakeDatabase: database}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.ObserveDeviceAliasVersion(ctx, identity, 1); !errors.Is(err, context.Canceled) || database.beginCalls != 0 {
		t.Fatal("canceled compatibility observation starts I/O")
	}
	if err := store.ObserveDeviceAliasVersion(t.Context(), identity, 2); !errors.Is(err, ErrInvalidStore) || database.beginCalls != 0 {
		t.Fatal("unknown compatibility version admitted")
	}
}
