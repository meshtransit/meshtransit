package postgres

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/node"
)

func TestLockBrowserResumeDevice(t *testing.T) {
	t.Parallel()
	for _, scenario := range []struct {
		name                                            string
		owner, profile                                  int64
		device, machine                                 string
		current                                         bool
		changedMachine, changedNode, absent, nodeAbsent bool
		allow                                           bool
		reason                                          string
		handoverTo                                      int64
		handover                                        bool
	}{
		{name: "same owner profile and keys", owner: 11, profile: 601, device: "active", machine: "active", current: true, allow: true},
		{name: "other owner", owner: 12, profile: 601, device: "active", machine: "active", current: true},
		{name: "other profile", owner: 11, profile: 602, device: "active", machine: "active", current: true},
		{name: "suspended Device", owner: 11, profile: 601, device: "suspended", machine: "active", current: true, reason: "admin"},
		{name: "handover to the signing member", owner: 12, profile: 601, device: "suspended", machine: "active",
			current: true, reason: "handover", handoverTo: 11, allow: true, handover: true},
		{name: "handover to someone else", owner: 12, profile: 601, device: "suspended", machine: "active",
			current: true, reason: "handover", handoverTo: 13},
		{name: "old owner during handover", owner: 11, profile: 601, device: "suspended", machine: "active",
			current: true, reason: "handover", handoverTo: 13},
		{name: "handover on another profile", owner: 12, profile: 602, device: "suspended", machine: "active",
			current: true, reason: "handover", handoverTo: 11},
		{name: "revoked machine", owner: 11, profile: 601, device: "active", machine: "revoked", current: true},
		{name: "expired machine", owner: 11, profile: 601, device: "active", machine: "expired", current: true},
		{name: "deleted Device or future machine", owner: 11, profile: 601, device: "active", machine: "active"},
		{name: "machine material mismatch", owner: 11, profile: 601, device: "active", machine: "active", current: true, changedMachine: true},
		{name: "Node material mismatch", owner: 11, profile: 601, device: "active", machine: "active", current: true, changedNode: true},
		{name: "missing active Node", owner: 11, profile: 601, device: "active", machine: "active", current: true, nodeAbsent: true},
		{name: "new machine", absent: true, allow: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			machine, err := node.NewMachineKey([32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			key, err := node.NewKey([32]byte{2})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := node.NewRegistrationIdentity(machine, key)
			if err != nil {
				t.Fatal(err)
			}
			tx := newFakeRegistrationDatabaseTransaction()
			row := registrationTestRow{scan: func(d ...any) error {
				*d[0].(*int64) = 501
				*d[1].(*string) = testRegistrationNodePublicID
				*d[2].(*int64) = scenario.profile
				*d[3].(*string) = "stable-device"
				*d[4].(*int64) = 4
				material := machine.Bytes()
				if scenario.changedMachine {
					material[0]++
				}
				*d[5].(*[]byte) = append([]byte(nil), material[:]...)
				*d[6].(*int64) = scenario.owner
				*d[7].(*string) = scenario.device
				*d[8].(*string) = scenario.machine
				*d[9].(*bool) = scenario.current
				*d[10].(*string) = scenario.reason
				*d[11].(*int64) = scenario.handoverTo
				return nil
			}}
			if scenario.absent {
				row = registrationTestRow{err: pgx.ErrNoRows}
			}
			tx.enqueueRow(lockBrowserResumeDeviceSQL, row)
			nodeRow := registrationTestRow{scan: func(d ...any) error {
				material := key.Bytes()
				if scenario.changedNode {
					material[0]++
				}
				*d[0].(*[]byte) = append([]byte(nil), material[:]...)
				return nil
			}}
			if scenario.nodeAbsent {
				nodeRow = registrationTestRow{err: pgx.ErrNoRows}
			}
			tx.enqueueRow(lockBrowserResumeNodeSQL, nodeRow)
			resumed, record, err := lockBrowserResumeDevice(t.Context(), tx, identity, browserCompletionAuthority{principalInternalID: 11, profileInternalID: 601, ephemeralMode: "persistent"})
			if !scenario.allow {
				if !errors.Is(err, ErrBrowserCompletionConflict) || resumed || record.internalID != 0 {
					t.Fatalf("unsafe resume = %v/%v", resumed, err)
				}
				return
			}
			if err != nil || resumed == scenario.absent {
				t.Fatalf("resume = %v/%v", resumed, err)
			}
			if record.handover != scenario.handover {
				t.Fatalf("handover = %t, want %t", record.handover, scenario.handover)
			}
			if resumed && (!bytes.Equal(record.nodeKey, []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) || record.publicID != testRegistrationNodePublicID) {
				t.Fatal("identity was not preserved")
			}
			for _, call := range tx.calls {
				if call.query == resumeBrowserDeviceSQL {
					t.Fatal("validation mutated Device")
				}
			}
		})
	}
}
