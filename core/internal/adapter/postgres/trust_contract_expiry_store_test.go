package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing/contractexpiry"
)

const (
	expiryTestDeployment = "01890f00-0000-7000-8000-000000000001"
	expiryTestContract   = "01890f00-0000-7000-8000-000000000010"
	expiryTestOther      = "01890f00-0000-7000-8000-000000000011"
)

func expiryFixture(t *testing.T) (deployment.ID, sharing.ContractID) {
	t.Helper()
	installation, err := deployment.ParseID(expiryTestDeployment)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := sharing.ParseContractID(expiryTestContract)
	if err != nil {
		t.Fatal(err)
	}
	return installation, contract
}

type expiryTestTransaction struct {
	fakeOutboxTransaction
	mode                string
	cancel              context.CancelFunc
	prepares, finalizes int
}

func (transaction *expiryTestTransaction) proof(args []any) trustContractExpiryProof {
	contract, change := args[1].(string), args[2].(string)
	proof := trustContractExpiryProof{
		Changed: true, TransactionID: "123", ChangeID: change, ContractID: contract,
		AggregateKind: "trust_contract", AggregateID: contract, AggregateVersion: 3, Action: "trust_contract.expired",
		Events: []trustContractExpiryEvidence{
			{WorkspaceID: "01890f00-0000-7000-8000-000000000101", NetworkID: "01890f00-0000-7000-8000-000000000201", StreamID: 1, Sequence: 1, PreviousHash: strings.Repeat("00", 32), NetworkRevision: 2, SharingRevision: 2, AuditPayload: `{"reason":"expired"}`, OutboxPayload: `{"subsystem":"sharing"}`},
			{WorkspaceID: "01890f00-0000-7000-8000-000000000102", NetworkID: "01890f00-0000-7000-8000-000000000202", StreamID: 2, Sequence: 4, PreviousHash: strings.Repeat("11", 32), NetworkRevision: 5, SharingRevision: 5, AuditPayload: `{"reason":"expired"}`, OutboxPayload: `{"subsystem":"sharing"}`},
		},
	}
	switch transaction.mode {
	case "foreign contract":
		proof.ContractID, proof.AggregateID = expiryTestOther, expiryTestOther
	case "wrong change":
		proof.ChangeID = expiryTestOther
	case "wrong action":
		proof.Action = "trust_contract.revoked"
	case "duplicate stream":
		proof.Events[1].StreamID = 1
	case "malformed hash":
		proof.Events[0].PreviousHash = strings.Repeat("z", 64)
	case "presigned event":
		proof.Events[0].EventHash = strings.Repeat("aa", 32)
	case "cancel":
		transaction.cancel()
	}
	return proof
}

func (transaction *expiryTestTransaction) QueryRow(ctx context.Context, query string, args ...any) outboxRow {
	switch query {
	case prepareTrustContractExpirySQL:
		transaction.prepares++
		return fakeOutboxRow{scan: func(values ...any) error {
			if transaction.mode == "query error" || transaction.mode == "cleanup" {
				return errors.New("synthetic prepare failure")
			}
			body, err := json.Marshal(transaction.proof(args))
			if err != nil {
				return err
			}
			switch transaction.mode {
			case "unchanged":
				body = []byte(`{"changed":false,"events":[]}`)
			case "unchanged with evidence":
				body = []byte(`{"changed":false,"events":[],"action":"trust_contract.expired"}`)
			case "missing changed":
				body = []byte(`{"events":[]}`)
			case "unknown field":
				body = []byte(`{"changed":false,"events":[],"deadline":"x"}`)
			}
			*values[0].(*[]byte) = body
			return nil
		}}
	case finalizeTrustContractExpirySQL:
		transaction.finalizes++
		return fakeOutboxRow{scan: func(values ...any) error {
			if transaction.mode == "finalize" {
				return errors.New("synthetic finalization failure")
			}
			var events []trustContractExpiryEvidence
			if err := json.Unmarshal(args[3].([]byte), &events); err != nil || len(events) != 2 {
				return errors.New("invalid evidence envelope")
			}
			for _, event := range events {
				if event.EventID == "" || event.OutboxID == "" || len(event.EventHash) != 64 || event.EventID == event.OutboxID {
					return errors.New("unhashed evidence")
				}
			}
			if events[0].EventID == events[1].EventID {
				return errors.New("reused event id")
			}
			count := 2
			if transaction.mode == "short finalize" {
				count = 1
			}
			*values[0].(*int) = count
			return ctx.Err()
		}}
	default:
		return fakeOutboxRow{scan: func(...any) error { return errors.New("unexpected expiry query") }}
	}
}

func TestTrustContractExpiryFinalizesOnceAndNeverRetriesUnknownCommit(t *testing.T) {
	t.Parallel()
	succeeding := map[string]bool{"expire": true, "unchanged": true}
	for _, name := range []string{
		"expire", "unchanged", "unchanged with evidence", "missing changed", "unknown field", "foreign contract",
		"wrong change", "wrong action", "duplicate stream", "malformed hash", "presigned event", "query error",
		"cancel", "configure", "finalize", "short finalize", "commit", "cleanup", "begin",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			installation, contract := expiryFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			transaction := &expiryTestTransaction{mode: name, cancel: cancel}
			database := &fakeOutboxDatabase{transaction: transaction}
			failure := errors.New("synthetic expiry failure")
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
			store := &TrustContractExpiryStore{database: database}
			changed, err := store.Expire(ctx, installation, contract)
			if succeeding[name] {
				if err != nil || changed != (name == "expire") || !transaction.committed || transaction.rollbackCalls != 0 {
					t.Fatalf("Expire() = %v, %v", changed, err)
				}
				if wantFinalizes := map[bool]int{true: 1, false: 0}[name == "expire"]; transaction.finalizes != wantFinalizes {
					t.Fatalf("finalizes = %d, want %d", transaction.finalizes, wantFinalizes)
				}
			} else if err == nil || changed || transaction.committed || name != "begin" && transaction.rollbackCalls != 1 {
				t.Fatalf("failed expiry leaked state: changed=%v err=%v", changed, err)
			}
			if name == "commit" && !errors.Is(err, ErrTrustContractExpiryCommitUnknown) {
				t.Fatal("lost commit uncertainty classification")
			}
			if name == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost caller cancellation")
			}
			if transaction.prepares > 1 || transaction.finalizes > 1 || database.readOnly {
				t.Fatal("expiry retried or used a read-only write transaction")
			}
		})
	}
}

type expiryListTransaction struct {
	fakeOutboxTransaction
	body string
	args []any
}

func (transaction *expiryListTransaction) QueryRow(_ context.Context, query string, args ...any) outboxRow {
	if query != listExpiredTrustContractsSQL {
		return fakeOutboxRow{scan: func(...any) error { return errors.New("unexpected expiry query") }}
	}
	transaction.args = args
	return fakeOutboxRow{scan: func(values ...any) error {
		*values[0].(*[]byte) = []byte(transaction.body)
		return nil
	}}
}

func TestTrustContractExpiryListDecodesStrictKeysetPages(t *testing.T) {
	t.Parallel()
	first := `{"contract_id":"` + expiryTestContract + `","expires_at":"2026-10-06T12:00:00.000001+00:00"}`
	second := `{"contract_id":"` + expiryTestOther + `","expires_at":"2026-10-06T12:00:00.000001+00:00"}`
	tests := []struct {
		name     string
		body     string
		wantErr  bool
		wantDone bool
		wantLen  int
	}{
		{name: "final page", body: `{"items":[` + first + `],"done":true}`, wantDone: true, wantLen: 1},
		{name: "full page", body: `{"items":[` + first + `,` + second + `],"done":false}`, wantLen: 2},
		{name: "empty", body: `{"items":[],"done":true}`, wantDone: true},
		{name: "short page not done", body: `{"items":[` + first + `],"done":false}`, wantErr: true},
		{name: "reordered", body: `{"items":[` + second + `,` + first + `],"done":false}`, wantErr: true},
		{name: "missing done", body: `{"items":[]}`, wantErr: true},
		{name: "null items", body: `{"items":null,"done":true}`, wantErr: true},
		{name: "unknown field", body: `{"items":[],"done":true,"cursor":{}}`, wantErr: true},
		{name: "invalid contract", body: `{"items":[{"contract_id":"x","expires_at":"2026-10-06T12:00:00Z"}],"done":true}`, wantErr: true},
		{name: "trailing value", body: `{"items":[],"done":true} {}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			installation, _ := expiryFixture(t)
			transaction := &expiryListTransaction{body: test.body}
			database := &fakeOutboxDatabase{transaction: transaction}
			store := &TrustContractExpiryStore{database: database}
			page, err := store.List(t.Context(), installation, contractexpiry.Cursor{}, 2)
			if (err != nil) != test.wantErr {
				t.Fatalf("List() error = %v, wantErr %v", err, test.wantErr)
			}
			if !database.readOnly {
				t.Fatal("discovery must use a read-only transaction")
			}
			if transaction.args[1] != nil || transaction.args[2] != nil {
				t.Fatal("a fresh sweep must not send a cursor")
			}
			if test.wantErr {
				if transaction.committed || transaction.rollbackCalls != 1 {
					t.Fatal("rejected page committed")
				}
				return
			}
			if page.Done != test.wantDone || len(page.Items) != test.wantLen {
				t.Fatalf("page = %+v", page)
			}
			if !test.wantDone && page.Next != (contractexpiry.Cursor{ExpiresAt: page.Items[1].ExpiresAt, ContractID: page.Items[1].ContractID}) {
				t.Fatalf("Next = %+v", page.Next)
			}
		})
	}
}

func TestTrustContractExpiryRejectsUnsafeConstructionAndInput(t *testing.T) {
	t.Parallel()
	for _, pool := range []*Pool{nil, {}, {role: PoolRoleRuntime, outboxDatabase: &fakeOutboxDatabase{}}} {
		if _, err := NewTrustContractExpiryStore(pool); !errors.Is(err, ErrInvalidTrustContractExpiry) {
			t.Fatal("non-worker pool accepted")
		}
	}
	installation, contract := expiryFixture(t)
	store := &TrustContractExpiryStore{database: &fakeOutboxDatabase{}}
	if _, err := store.Expire(t.Context(), deployment.ID{}, contract); !errors.Is(err, ErrInvalidTrustContractExpiry) {
		t.Fatal("missing installation accepted")
	}
	if _, err := store.Expire(t.Context(), installation, sharing.ContractID{}); !errors.Is(err, ErrInvalidTrustContractExpiry) {
		t.Fatal("missing contract accepted")
	}
	partial := contractexpiry.Cursor{ExpiresAt: time.Now()}
	if _, err := store.List(t.Context(), installation, partial, 2); !errors.Is(err, ErrInvalidTrustContractExpiry) {
		t.Fatal("partial cursor accepted")
	}
	if _, err := store.List(t.Context(), installation, contractexpiry.Cursor{}, 129); !errors.Is(err, ErrInvalidTrustContractExpiry) {
		t.Fatal("unbounded page accepted")
	}
}
