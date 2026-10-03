package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/sharing/devicealias"
)

func TestDeviceAliasWorkerOwnsCompleteChangeAndNeverRetriesUnknownCommit(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"reserve", "ready", "idempotent", "missing changed", "null proof", "foreign endpoint", "wrong change", "duplicate stream", "malformed hash", "wrong kind", "query error", "cancel", "configure", "finalize", "commit", "cleanup", "begin"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			intent := aliasWorkerIntentFixture(t)
			if name == "ready" {
				intent.Mode = devicealias.Ready
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
			valid := name == "reserve" || name == "ready" || name == "idempotent"
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
}

func (transaction *aliasWorkerTestTransaction) QueryRow(ctx context.Context, query string, args ...any) outboxRow {
	switch query {
	case prepareDeviceAliasChangeSQL:
		transaction.prepares++
		return fakeOutboxRow{scan: func(values ...any) error {
			if transaction.mode == "query error" || transaction.mode == "cleanup" {
				return errors.New("synthetic prepare failure")
			}
			kind, aggregate := "device_alias_lease", args[6].([]string)[0]
			if transaction.intent.Mode == devicealias.Ready {
				kind, aggregate = "device_alias_client_readiness", args[7].(string)
			}
			proof := deviceAliasChangeProof{Changed: true, TransactionID: "123", ChangeID: args[8].(string), EndpointID: transaction.intent.EndpointID.String(),
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
	case finalizeDeviceAliasChangeSQL:
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
