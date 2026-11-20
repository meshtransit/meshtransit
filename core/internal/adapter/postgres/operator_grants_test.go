package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/core/migrations"
)

// grantsTransaction answers the operator grants' reads from fixed values
// and records every statement.
type grantsTransaction struct {
	superuser   bool
	needs       bool
	holdsCreate bool
	selfGrants  []string
	statements  []string
}

func (transaction *grantsTransaction) Exec(_ context.Context, statement string, _ ...any) error {
	transaction.statements = append(transaction.statements, statement)
	return nil
}

func (transaction *grantsTransaction) QueryRow(_ context.Context, statement string, _ ...any) migrationRow {
	switch {
	case strings.Contains(statement, "rolsuper"):
		return grantsRow{values: []any{transaction.superuser}}
	case statement == operatorNeedsMigratorSQL:
		return grantsRow{values: []any{transaction.needs}}
	case strings.Contains(statement, "has_schema_privilege($2, $1, 'CREATE')"):
		return grantsRow{values: []any{true, transaction.holdsCreate}}
	case strings.Contains(statement, "array_agg"):
		return grantsRow{values: []any{transaction.selfGrants}}
	}
	return grantsRow{err: errors.New("unexpected query: " + statement)}
}

func (*grantsTransaction) Query(context.Context, string, ...any) (migrationRows, error) {
	return nil, errors.New("unexpected query")
}
func (*grantsTransaction) Commit(context.Context) error   { return nil }
func (*grantsTransaction) Rollback(context.Context) error { return nil }

type grantsRow struct {
	values []any
	err    error
}

func (row grantsRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	for index, destination := range destinations {
		switch target := destination.(type) {
		case *bool:
			*target = row.values[index].(bool)
		case *[]string:
			*target = slices.Clone(row.values[index].([]string))
		}
	}
	return nil
}

func ownershipStep() migrations.OperatorStep {
	return migrations.OperatorStep{Kind: migrations.OperatorStepOwnership, Effects: []migrations.OperatorEffect{
		{Kind: migrations.OperatorEffectOwner, Role: "mesh_owner_a"},
		{Kind: migrations.OperatorEffectOwner, Role: "mesh_owner_a"},
	}}
}

// A superuser operator needs nothing: no GRANT or REVOKE at any stage.
func TestOperatorGrantsSuperuserIssuesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	transaction := &grantsTransaction{superuser: true, needs: true}
	grants := &operatorGrants{}
	for _, stage := range []func() error{
		func() error { return grants.begin(ctx, transaction) },
		func() error { return grants.prepare(ctx, transaction, ownershipStep()) },
		func() error { return grants.releaseSchemas(ctx, transaction) },
		func() error { return grants.releaseMemberships(ctx, transaction) },
	} {
		if err := stage(); err != nil {
			t.Fatal(err)
		}
	}
	if len(transaction.statements) != 0 {
		t.Fatalf("statements = %q, want none", transaction.statements)
	}
}

// An operator that can read the schema already does not join the migrator
// at begin (it may hold no ADMIN on it).
func TestOperatorGrantsBeginJoinsOnlyWhenNeeded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, needs := range []bool{false, true} {
		transaction := &grantsTransaction{needs: needs}
		if err := (&operatorGrants{}).begin(ctx, transaction); err != nil {
			t.Fatal(err)
		}
		joined := slices.ContainsFunc(transaction.statements, func(statement string) bool {
			return strings.HasPrefix(statement, `GRANT "mesh_migrator" TO CURRENT_USER`)
		})
		if joined != needs {
			t.Fatalf("needs=%v: statements = %q", needs, transaction.statements)
		}
	}
}

// An ownership step joins the migrator and each new owner once, grants each
// owner CREATE on the schemas it lacks, and releaseSchemas takes back
// exactly those; a role step needs nothing.
func TestOperatorGrantsPrepareAndRelease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	transaction := &grantsTransaction{}
	grants := &operatorGrants{}
	if err := grants.prepare(ctx, transaction, migrations.OperatorStep{Kind: migrations.OperatorStepRole}); err != nil {
		t.Fatal(err)
	}
	if len(transaction.statements) != 0 {
		t.Fatalf("role step statements = %q", transaction.statements)
	}
	for range 2 {
		if err := grants.prepare(ctx, transaction, ownershipStep()); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		`GRANT "mesh_migrator" TO CURRENT_USER WITH INHERIT TRUE, SET TRUE`,
		`GRANT "mesh_owner_a" TO CURRENT_USER WITH INHERIT TRUE, SET TRUE`,
		`GRANT CREATE ON SCHEMA "mesh" TO "mesh_owner_a"`,
		`GRANT CREATE ON SCHEMA "mesh_ops" TO "mesh_owner_a"`,
		`GRANT CREATE ON SCHEMA "mesh_audit" TO "mesh_owner_a"`,
	}
	if !slices.Equal(transaction.statements, want) {
		t.Fatalf("prepare statements = %q, want %q", transaction.statements, want)
	}
	transaction.statements = nil
	if err := grants.releaseSchemas(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	if len(transaction.statements) != 3 || !strings.HasPrefix(transaction.statements[0], "REVOKE CREATE ON SCHEMA") {
		t.Fatalf("release statements = %q", transaction.statements)
	}
	transaction.statements = nil
	transaction.selfGrants = []string{"mesh_migrator", "mesh_owner_a"}
	if err := grants.releaseMemberships(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	want = []string{
		`REVOKE "mesh_migrator" FROM CURRENT_USER GRANTED BY CURRENT_USER`,
		`REVOKE "mesh_owner_a" FROM CURRENT_USER GRANTED BY CURRENT_USER`,
	}
	if !slices.Equal(transaction.statements, want) {
		t.Fatalf("membership statements = %q, want %q", transaction.statements, want)
	}
}

// An owner role that already holds CREATE is granted nothing and so loses
// nothing at release.
func TestOperatorGrantsKeepsExistingCreate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	transaction := &grantsTransaction{holdsCreate: true}
	grants := &operatorGrants{}
	if err := grants.prepare(ctx, transaction, ownershipStep()); err != nil {
		t.Fatal(err)
	}
	transaction.statements = nil
	if err := grants.releaseSchemas(ctx, transaction); err != nil {
		t.Fatal(err)
	}
	if len(transaction.statements) != 0 {
		t.Fatalf("release statements = %q, want none", transaction.statements)
	}
}

// A membership the operator joined for the transaction is not reported;
// any other is.
func TestOperatorGrantsWithoutJoined(t *testing.T) {
	t.Parallel()
	grants := &operatorGrants{joined: []string{"mesh_migrator"}}
	report := OperatorReport{Memberships: []string{
		"doadmin is a member of mesh_migrator", "doadmin is a member of mesh_runtime",
		"mesh_runtime is a member of mesh_migrator",
	}}
	got := grants.withoutJoined(report, "doadmin").Memberships
	want := []string{"doadmin is a member of mesh_runtime", "mesh_runtime is a member of mesh_migrator"}
	if !slices.Equal(got, want) {
		t.Fatalf("memberships = %q, want %q", got, want)
	}
	if len(report.Memberships) != 3 {
		t.Fatal("withoutJoined changed its input")
	}
}

// Status succeeds on its own rollback, not when the rollback failed too.
func TestStatusRolledBack(t *testing.T) {
	t.Parallel()
	ended := fmt.Errorf("%w: %w", ErrMigrationRun, errOperatorStatusRolledBack)
	if !statusRolledBack(ended) {
		t.Fatal("the status rollback is the expected end")
	}
	if statusRolledBack(errors.Join(ended, fmt.Errorf("%w: %w", errMigrationRollback, errors.New("conn closed")))) {
		t.Fatal("a failed rollback must surface")
	}
	if statusRolledBack(errors.New("query failed")) {
		t.Fatal("another error is not a rollback")
	}
}
