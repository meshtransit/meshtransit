package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// scriptedGuardrailDatabase answers each statement of a guardrail change by
// its SQL; the bump fails with MTG03 (a share changed under the change) for
// the first conflicts attempts.
type scriptedGuardrailDatabase struct {
	saved     string
	inventory string
	conflicts int
	begins    int
	bumps     int
	commits   int
}

func (database *scriptedGuardrailDatabase) Begin(context.Context) (accountSessionTransaction, error) {
	database.begins++
	return &scriptedGuardrailTransaction{database: database}, nil
}

type scriptedGuardrailTransaction struct{ database *scriptedGuardrailDatabase }

func (*scriptedGuardrailTransaction) Exec(context.Context, string, ...any) error { return nil }

func (transaction *scriptedGuardrailTransaction) QueryRow(_ context.Context, query string,
	_ ...any) accountSessionRow {
	database := transaction.database
	switch query {
	case changeWorkspaceGuardrailSQL:
		return fakeAccountSessionRow{values: []any{database.saved, nil, "", "", int64(1), int64(1), int64(1)}}
	case guardrailChangeShareContractsSQL:
		return fakeAccountSessionRow{values: []any{database.inventory}}
	case bumpGuardrailShareNetworksSQL:
		database.bumps++
		if database.bumps <= database.conflicts {
			return fakeAccountSessionRow{err: &pgconn.PgError{Code: "MTG03"}}
		}
		return fakeAccountSessionRow{values: []any{"[]"}}
	case lockWorkspaceStreamHeadSQL:
		return fakeAccountSessionRow{values: []any{int64(1), int64(9), make([]byte, 32)}}
	case appendGuardrailEvidenceSQL:
		return fakeAccountSessionRow{values: []any{int64(9)}}
	default:
		return fakeAccountSessionRow{err: errors.New("unexpected statement")}
	}
}

func (transaction *scriptedGuardrailTransaction) Commit(context.Context) error {
	transaction.database.commits++
	return nil
}

func (*scriptedGuardrailTransaction) Rollback(context.Context) error { return nil }

// A change that a concurrent share made or ended under is redone as a whole,
// at most three attempts in all, then answered as a version conflict; any
// other conflict is never retried.
func TestGuardrailChangeRetriesWhenSharesChanged(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID(shareStoreWorkspace)
	id, _ := publicid.Parse(shareStoreGuardrail)
	correlationID, _ := publicid.Parse("01890f00-0000-7000-8000-000000000a04")
	// Locks incoming shares of a Network that only provides one: nothing is
	// cut, so the bump answers no Network.
	spec := shareStoreSpec(t, guardrail.ModeEnforce)
	spec.Sharing.Direction = guardrail.DirectionIncoming
	saved := guardrail.Guardrail{ID: id, Version: 1, Spec: spec}
	inventory := shareStoreInventory(t, saved)
	preview, err := guardrail.ComputeImpact(workspaceID, nil, guardrail.Candidate{Spec: spec},
		mustInventory(t, inventory).Contracts)
	if err != nil {
		t.Fatal(err)
	}
	params, err := spec.ParamsDocument()
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]any{"guardrail_id": id.String(), "kind": spec.Kind, "name": spec.Name,
		"description": spec.Description, "mode": spec.Mode, "params": json.RawMessage(params), "version": 1,
		"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "state": "active"})
	if err != nil {
		t.Fatal(err)
	}
	change := guardrail.Change{
		Session: accountSessionManagementScopeSession(t, time.Now().UTC()), WorkspaceID: workspaceID,
		Operation: guardrail.OperationCreate, GuardrailID: id, Spec: spec,
		Permission: authorization.PermissionGuardrailManage, CorrelationID: correlationID, ImpactHash: preview.Hash,
	}
	for _, test := range []struct {
		name      string
		conflicts int
		begins    int
		committed bool
	}{
		{name: "no conflict", conflicts: 0, begins: 1, committed: true},
		{name: "two conflicts, third attempt commits", conflicts: 2, begins: 3, committed: true},
		{name: "conflicts on every attempt", conflicts: 3, begins: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			database := &scriptedGuardrailDatabase{saved: string(document), inventory: inventory, conflicts: test.conflicts}
			var waits []int
			store := &GuardrailStore{database: database,
				options: AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: time.Second},
				limits:  GuardrailShareLimits{Impact: 10, WakeNetworks: 10},
				retryDelay: func(attempt int) time.Duration {
					waits = append(waits, attempt)
					return 0
				}}
			result, err := store.Change(t.Context(), change)
			if database.begins != test.begins || (database.commits == 1) != test.committed {
				t.Fatalf("begins %d, commits %d; want %d, committed %v (%v)", database.begins, database.commits,
					test.begins, test.committed, err)
			}
			if test.committed {
				if err != nil || result.Guardrail.ID != id || len(waits) != test.conflicts {
					t.Fatalf("result %+v, %v, waits %v", result, err, waits)
				}
				return
			}
			if !errors.Is(err, guardrail.ErrVersionConflict) || len(waits) != 2 {
				t.Fatalf("exhausted retries: %v, waits %v", err, waits)
			}
		})
	}
	// A stale guardrail version (40001) is the caller's to resolve.
	stale := guardrailDatabaseError(&pgconn.PgError{Code: "40001"})
	if !errors.Is(stale, guardrail.ErrVersionConflict) || errors.Is(stale, errGuardrailSharesChanged) {
		t.Fatalf("40001 = %v", stale)
	}
}

func TestJitteredGuardrailRetryDelay(t *testing.T) {
	t.Parallel()
	for attempt := 2; attempt <= maximumGuardrailChangeAttempts; attempt++ {
		delay := jitteredGuardrailRetryDelay(attempt)
		if delay < time.Duration(attempt)*10*time.Millisecond || delay > time.Duration(attempt)*41*time.Millisecond {
			t.Fatalf("attempt %d waits %v", attempt, delay)
		}
	}
}
