package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/sharing/devicealias"
)

func TestDeviceAliasWorkerOwnsCompleteChangeAndNeverRetriesUnknownCommit(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"reserve", "ready", "withdraw", "quarantine_consumer", "quarantine_resource", "wrong withdrawal action", "commit then cancel", "idempotent", "missing changed", "null proof", "foreign endpoint", "wrong change", "duplicate stream", "malformed hash", "wrong kind", "query error", "cancel", "configure", "finalize", "commit", "cleanup", "begin"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			intent := aliasWorkerIntentFixture(t)
			if devicealias.ChangeMode(name).IsValid() {
				intent.Mode = devicealias.ChangeMode(name)
			}
			if name == "wrong withdrawal action" {
				intent.Mode = devicealias.Withdraw
			}
			if intent.Mode.Withdraws() {
				intent.ProviderNodeEpoch, intent.ConsumerNodeEpoch = 0, 0
			}
			if intent.Mode == devicealias.QuarantineResource {
				intent.ConsumerID = node.ID{}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			transaction := &aliasWorkerTestTransaction{mode: name, intent: intent, cancel: cancel}
			failure := errors.New("synthetic alias worker failure")
			database := &fakeOutboxDatabase{transaction: transaction}
			switch name {
			case "configure":
				transaction.execErr = failure
			case "commit":
				transaction.commitErr = failure
			case "cleanup":
				transaction.rollbackErr = failure
			case "begin":
				database.beginErr = failure
			}
			store := &DeviceAliasWorkerStore{database: database}
			changed, err := store.Change(ctx, intent)
			valid := devicealias.ChangeMode(name).IsValid() || name == "idempotent" || name == "commit then cancel"
			if valid {
				if err != nil || changed != (name != "idempotent") || !transaction.committed || transaction.rollbackCalls != 0 {
					t.Fatal("incomplete alias change reported success", err)
				}
				if transaction.finalizes != 1 && name != "idempotent" || transaction.finalizes != 0 && name == "idempotent" {
					t.Fatal("idempotent change created evidence")
				}
			} else if err == nil || changed || transaction.rollbackCalls != 1 || transaction.committed {
				t.Fatal("failed alias change leaked state", err)
			}
			if name == "commit" && !errors.Is(err, ErrDeviceAliasCommitUnknown) {
				t.Fatal("lost commit uncertainty classification")
			}
			if name == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost caller cancellation")
			}
			if transaction.prepares > 1 || transaction.finalizes > 1 || database.readOnly {
				t.Fatal("change retried or used a read-only write transaction")
			}
		})
	}
}

func TestDeviceAliasWorkerRejectsUnsafeConstructionAndIntent(t *testing.T) {
	t.Parallel()
	for _, pool := range []*Pool{nil, {}, {role: PoolRoleRuntime, outboxDatabase: &fakeOutboxDatabase{}}} {
		if _, err := NewDeviceAliasWorkerStore(pool); !errors.Is(err, ErrInvalidDeviceAliasWorker) {
			t.Fatal("non-worker pool accepted")
		}
	}
	store := &DeviceAliasWorkerStore{database: &fakeOutboxDatabase{}}
	if _, err := store.Change(t.Context(), devicealias.ChangeIntent{}); !errors.Is(err, ErrInvalidDeviceAliasWorker) {
		t.Fatal("incomplete intent accepted")
	}
}

func aliasWorkerIntentFixture(t *testing.T) devicealias.ChangeIntent {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	endpointID, err := sharing.ParsePrivateEndpointID("01890f00-0000-7000-8000-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	consumerID, err := node.ParseID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	return devicealias.ChangeIntent{DeploymentID: deploymentID, EndpointID: endpointID, ConsumerID: consumerID, EndpointGeneration: 1, ProviderNodeEpoch: 1, ConsumerNodeEpoch: 1, Mode: devicealias.Reserve}
}

type aliasWorkerTestTransaction struct {
	fakeOutboxTransaction
	mode                string
	intent              devicealias.ChangeIntent
	cancel              context.CancelFunc
	prepares, finalizes int
	// version is the granted worker version (schema 147: 3, schema 170: 4);
	// prepared records the prepare queries run.
	version  int
	prepared []string
}

func (transaction *aliasWorkerTestTransaction) QueryRow(ctx context.Context, query string, args ...any) outboxRow {
	switch query {
	case deviceAliasWorkerVersionSQL:
		return fakeOutboxRow{scan: func(values ...any) error {
			*values[0].(*int) = max(transaction.version, 2)
			return nil
		}}
	case prepareDeviceAliasChangeSQL, prepareScaledDeviceAliasChangeSQL, prepareReadmittingDeviceAliasChangeSQL, prepareDeviceAliasWithdrawalSQL,
		prepareDeviceAliasResourceQuarantineSQL:
		transaction.prepares++
		transaction.prepared = append(transaction.prepared, query)
		return fakeOutboxRow{scan: func(values ...any) error {
			if transaction.mode == "query error" || transaction.mode == "cleanup" {
				return errors.New("synthetic prepare failure")
			}
			kind, aggregate := "device_alias_lease", "01890f00-0000-7000-8000-000000000801"
			change, action := "", ""
			if transaction.intent.Mode.Withdraws() {
				if transaction.intent.Mode == devicealias.QuarantineResource {
					change = args[3].(string)
				} else {
					change = args[4].(string)
				}
				action = "sharing.device_alias." + string(transaction.intent.Mode)
			}

			if !transaction.intent.Mode.Withdraws() {
				aggregate, change, action = args[6].([]string)[0], args[8].(string), ""
			}
			if transaction.intent.Mode == devicealias.Ready || transaction.intent.Mode == devicealias.Withdraw {
				kind = "device_alias_client_readiness"
			}
			if transaction.mode == "wrong withdrawal action" {
				action = "sharing.device_alias.ready"
			}
			proof := deviceAliasChangeProof{Changed: true, TransactionID: "123", Action: action, ChangeID: change, EndpointID: transaction.intent.EndpointID.String(),
				AggregateKind: kind, AggregateID: aggregate, AggregateVersion: 1, Deadline: time.Now().Add(time.Minute), Events: []deviceAliasEvidence{
					{WorkspaceID: "01890f00-0000-7000-8000-000000000101", NetworkID: "01890f00-0000-7000-8000-000000000201", StreamID: 1, Sequence: 1, PreviousHash: strings.Repeat("00", 32), NetworkRevision: 2, SharingRevision: 2, AuditPayload: `{"network_revision":2}`, OutboxPayload: `{"subsystem":"sharing"}`},
					{WorkspaceID: "01890f00-0000-7000-8000-000000000102", NetworkID: "01890f00-0000-7000-8000-000000000202", StreamID: 2, Sequence: 3, PreviousHash: strings.Repeat("11", 32), NetworkRevision: 4, SharingRevision: 4, AuditPayload: `{"network_revision":4}`, OutboxPayload: `{"subsystem":"sharing"}`},
				}}
			switch transaction.mode {
			case "foreign endpoint":
				proof.EndpointID = transaction.intent.ConsumerID.String()
			case "wrong change":
				proof.ChangeID = transaction.intent.ConsumerID.String()
			case "duplicate stream":
				proof.Events[1].StreamID = 1
			case "malformed hash":
				proof.Events[0].PreviousHash = strings.Repeat("z", 64)
			case "wrong kind":
				proof.AggregateKind = "resource_export"
			case "cancel":
				transaction.cancel()
			}
			body, err := json.Marshal(proof)
			if err != nil {
				return err
			}
			switch transaction.mode {
			case "idempotent":
				body = []byte(`{"changed":false,"events":[]}`)
			case "missing changed":
				body = []byte(`{"events":[]}`)
			case "null proof":
				body = []byte(`null`)
			}
			*values[0].(*[]byte) = body
			return nil
		}}
	case finalizeDeviceAliasChangeSQL, finalizeDeviceAliasWithdrawalSQL:
		transaction.finalizes++
		return fakeOutboxRow{scan: func(values ...any) error {
			if transaction.mode == "finalize" {
				return errors.New("synthetic finalization failure")
			}
			var events []deviceAliasEvidence
			if err := json.Unmarshal(args[5].([]byte), &events); err != nil || len(events) != 2 {
				return errors.New("invalid evidence envelope")
			}
			for _, event := range events {
				if event.EventID == "" || event.OutboxID == "" || len(event.EventHash) != 64 {
					return errors.New("unhashed evidence")
				}
			}
			*values[0].(*int) = 2
			return ctx.Err()
		}}
	default:
		return fakeOutboxRow{scan: func(...any) error { return errors.New("unexpected alias query") }}
	}
}

func (transaction *aliasWorkerTestTransaction) Commit(ctx context.Context) error {
	err := transaction.fakeOutboxTransaction.Commit(ctx)
	if err == nil && transaction.mode == "commit then cancel" {
		transaction.cancel()
	}
	return err
}

// TestDeviceAliasWorkerUsesNewestPrepareGranted: reservation and readiness
// go through prepare v4 (schema 170) once the worker may run it and load work
// v3, else through v3 (schema 147) once granted, and through v2 until then;
// withdrawals keep their own entry points.
func TestDeviceAliasWorkerUsesNewestPrepareGranted(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		mode    devicealias.ChangeMode
		version int
		want    string
	}{
		{devicealias.Reserve, 2, prepareDeviceAliasChangeSQL},
		{devicealias.Reserve, 3, prepareScaledDeviceAliasChangeSQL},
		{devicealias.Ready, 3, prepareScaledDeviceAliasChangeSQL},
		{devicealias.Reserve, 4, prepareReadmittingDeviceAliasChangeSQL},
		{devicealias.Ready, 4, prepareReadmittingDeviceAliasChangeSQL},
		{devicealias.Withdraw, 4, prepareDeviceAliasWithdrawalSQL},
	} {
		intent := aliasWorkerIntentFixture(t)
		intent.Mode = test.mode
		if intent.Mode.Withdraws() {
			intent.ProviderNodeEpoch, intent.ConsumerNodeEpoch = 0, 0
		}
		transaction := &aliasWorkerTestTransaction{mode: string(test.mode), intent: intent, version: test.version}
		store := &DeviceAliasWorkerStore{database: &fakeOutboxDatabase{transaction: transaction}}
		if _, err := store.Change(t.Context(), intent); err != nil {
			t.Fatalf("%s version=%d: %v", test.mode, test.version, err)
		}
		if len(transaction.prepared) != 1 || transaction.prepared[0] != test.want {
			t.Fatalf("%s version=%d prepared with %v", test.mode, test.version, transaction.prepared)
		}
	}
}
