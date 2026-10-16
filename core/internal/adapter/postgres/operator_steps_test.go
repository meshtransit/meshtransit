package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/migrations"
)

func operatorFixtureSteps() []migrations.OperatorStep {
	owner := func(name string, version int64, rollout bool, function string) migrations.OperatorStep {
		return migrations.OperatorStep{Name: name, Version: version, Kind: migrations.OperatorStepOwnership,
			AfterRollout: rollout, Effects: []migrations.OperatorEffect{
				{Kind: migrations.OperatorEffectOwner, Function: function, Role: "mesh_share_writer"},
				{Kind: migrations.OperatorEffectExecute, Function: function, Role: "mesh_runtime"},
			}}
	}
	return []migrations.OperatorStep{
		owner("000051_a_ownership", 51, false, "mesh_ops.a_v1(UUID)"),
		owner("000053_b_ownership", 53, true, "mesh_ops.b_v1(UUID)"),
		{Name: "000080_c_role", Version: 80, Kind: migrations.OperatorStepRole,
			Effects: []migrations.OperatorEffect{{Kind: migrations.OperatorEffectRole, Role: "mesh_c"}}},
		owner("000080_c_ownership", 80, true, "mesh_ops.c_v1(UUID)"),
		owner("000094_d_ownership", 94, false, "mesh_ops.d_v1(UUID)"),
		owner("000172_e_ownership", 172, false, "mesh_ops.e_v1(UUID)"),
	}
}

// summarizeOperatorSteps attributes each unmet requirement to its step and
// leaves the steps of migrations not applied yet out of the evaluation.
func TestSummarizeOperatorStepsReportsTheExactMissingFact(t *testing.T) {
	t.Parallel()
	steps := operatorFixtureSteps()
	due := dueOperatorSteps(steps, 171)
	requirements := migrations.OperatorRequirements(due)
	satisfied := make([]bool, len(requirements))
	for index := range satisfied {
		satisfied[index] = true
	}
	// 000094 granted, but its function still belongs to the migrator.
	for index, requirement := range requirements {
		if requirement.Step == "000094_d_ownership" && requirement.Effect.Kind == migrations.OperatorEffectOwner {
			satisfied[index] = false
		}
	}
	report, err := summarizeOperatorSteps(steps, requirements, satisfied, 171)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]OperatorStepState{}
	for _, step := range report.Steps {
		states[step.Name] = step.State
	}
	if states["000051_a_ownership"] != OperatorStepApplied || states["000094_d_ownership"] != OperatorStepPending ||
		states["000172_e_ownership"] != OperatorStepAwaitingMigration || states["000080_c_role"] != OperatorStepApplied {
		t.Fatalf("states = %v", states)
	}
	pending := report.Pending()
	if len(pending) != 1 || pending[0].Name != "000094_d_ownership" || len(pending[0].Missing) != 1 ||
		pending[0].Missing[0] != "owner of mesh_ops.d_v1(UUID) is not mesh_share_writer" {
		t.Fatalf("pending = %+v", pending)
	}
	if _, err := summarizeOperatorSteps(steps, requirements, satisfied[1:], 171); err == nil {
		t.Fatal("accepted a result that does not match the requirements")
	}
}

func operatorFixtureReport(states map[string]OperatorStepState, schemaVersion int64) OperatorReport {
	report := OperatorReport{CurrentSchemaVersion: schemaVersion}
	for _, step := range operatorFixtureSteps() {
		state := OperatorStepApplied
		if step.Kind == migrations.OperatorStepOwnership && step.Version > schemaVersion {
			state = OperatorStepAwaitingMigration
		}
		if override, ok := states[step.Name]; ok {
			state = override
		}
		report.Steps = append(report.Steps, OperatorStepStatus{Name: step.Name, Version: step.Version,
			Kind: string(step.Kind), AfterRollout: step.AfterRollout, State: state})
	}
	return report
}

func TestPlanOperatorStepsIsANoOpWhenEveryDueStepIsApplied(t *testing.T) {
	t.Parallel()
	plan, err := planOperatorSteps(operatorFixtureSteps(), operatorFixtureReport(nil, 171), OperatorApplyOptions{})
	if err != nil || len(plan.Run) != 0 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if len(plan.Waiting) != 1 || plan.Waiting[0].Step != "000172_e_ownership" ||
		plan.Waiting[0].Reason != OperatorWaitMigration {
		t.Fatalf("waiting = %+v", plan.Waiting)
	}
}

// From the earliest pending step on, every due step runs again in file order,
// so an earlier step never overrides a later one that already ran.
func TestPlanOperatorStepsReplaysInOrderFromTheEarliestPendingStep(t *testing.T) {
	t.Parallel()
	report := operatorFixtureReport(map[string]OperatorStepState{"000053_b_ownership": OperatorStepPending}, 171)
	plan, err := planOperatorSteps(operatorFixtureSteps(), report, OperatorApplyOptions{AfterRollout: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(plan.Run, ","); got != "000053_b_ownership,000080_c_role,000080_c_ownership,000094_d_ownership" {
		t.Fatalf("run = %s", got)
	}
}

// A step that waits for the rollout runs only with AfterRollout; until then
// it and every later pending step wait, and nothing after it runs.
func TestPlanOperatorStepsHoldsRolloutStepsAndEverythingAfterThem(t *testing.T) {
	t.Parallel()
	report := operatorFixtureReport(map[string]OperatorStepState{
		"000051_a_ownership": OperatorStepPending,
		"000080_c_ownership": OperatorStepPending,
		"000094_d_ownership": OperatorStepPending,
	}, 171)
	plan, err := planOperatorSteps(operatorFixtureSteps(), report, OperatorApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(plan.Run, ","); got != "000051_a_ownership,000053_b_ownership,000080_c_role" {
		t.Fatalf("run = %s", got)
	}
	waiting := map[string]OperatorWaitReason{}
	for _, wait := range plan.Waiting {
		waiting[wait.Step] = wait.Reason
	}
	if waiting["000080_c_ownership"] != OperatorWaitRollout || waiting["000094_d_ownership"] != OperatorWaitEarlierStep ||
		waiting["000172_e_ownership"] != OperatorWaitMigration || len(waiting) != 3 {
		t.Fatalf("waiting = %v", waiting)
	}
}

// Through names the newest migration whose steps may run; asking for a step
// whose migration is not applied is refused before anything runs.
func TestPlanOperatorStepsRefusesAStepBeforeItsMigration(t *testing.T) {
	t.Parallel()
	report := operatorFixtureReport(nil, 93)
	_, err := planOperatorSteps(operatorFixtureSteps(), report, OperatorApplyOptions{Through: 94})
	var refused *OperatorStepRefusedError
	if !errors.As(err, &refused) || !errors.Is(err, ErrOperatorStepRefused) || refused.Step != "000094_d_ownership" ||
		refused.Reason != OperatorWaitMigration {
		t.Fatalf("error = %v", err)
	}
	report = operatorFixtureReport(map[string]OperatorStepState{"000094_d_ownership": OperatorStepPending}, 171)
	plan, err := planOperatorSteps(operatorFixtureSteps(), report, OperatorApplyOptions{Through: 93})
	if err != nil || len(plan.Run) != 0 || len(plan.Waiting) != 2 || plan.Waiting[0].Reason != OperatorWaitThrough {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

func TestOperatorApplyVerificationRefusesARegressionOrAnUnappliedStep(t *testing.T) {
	t.Parallel()
	before := operatorFixtureReport(map[string]OperatorStepState{"000094_d_ownership": OperatorStepPending}, 171)
	after := operatorFixtureReport(nil, 171)
	if err := verifyOperatorApply(before, after, []string{"000094_d_ownership"}); err != nil {
		t.Fatalf("clean apply: %v", err)
	}
	regressed := operatorFixtureReport(map[string]OperatorStepState{"000051_a_ownership": OperatorStepPending}, 171)
	if err := verifyOperatorApply(before, regressed, []string{"000094_d_ownership"}); !errors.Is(err, ErrOperatorStepUnverified) {
		t.Fatalf("regression: %v", err)
	}
	if err := verifyOperatorApply(before, before, []string{"000094_d_ownership"}); !errors.Is(err, ErrOperatorStepUnverified) {
		t.Fatalf("step still pending: %v", err)
	}
}

// A role step never waits behind a held ownership step: the next migration
// may need its role.
func TestPlanOperatorStepsRunsRoleStepsBehindAHeldStep(t *testing.T) {
	t.Parallel()
	steps := append(operatorFixtureSteps(), migrations.OperatorStep{Name: "000175_f_role", Version: 175,
		Kind: migrations.OperatorStepRole, Effects: []migrations.OperatorEffect{{Kind: migrations.OperatorEffectRole, Role: "mesh_f"}}})
	report := operatorFixtureReport(map[string]OperatorStepState{"000053_b_ownership": OperatorStepPending}, 171)
	report.Steps = append(report.Steps, OperatorStepStatus{Name: "000175_f_role", Version: 175, Kind: "role",
		State: OperatorStepPending})
	plan, err := planOperatorSteps(steps, report, OperatorApplyOptions{})
	if err != nil || strings.Join(plan.Run, ",") != "000175_f_role" {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

type operatorSessionTransaction struct {
	execs     []string
	preflight []any
}

func (transaction *operatorSessionTransaction) Exec(_ context.Context, query string, arguments ...any) error {
	transaction.execs = append(transaction.execs, query+fmt.Sprint(arguments...))
	return nil
}

func (transaction *operatorSessionTransaction) QueryRow(context.Context, string, ...any) migrationRow {
	return fakeMigrationRow{values: transaction.preflight}
}

func (*operatorSessionTransaction) Query(context.Context, string, ...any) (migrationRows, error) {
	return nil, errors.New("unexpected query")
}
func (*operatorSessionTransaction) Commit(context.Context) error   { return nil }
func (*operatorSessionTransaction) Rollback(context.Context) error { return nil }

type operatorSessionConnection struct{ transaction *operatorSessionTransaction }

func (connection operatorSessionConnection) Begin(context.Context, bool) (migrationTransaction, error) {
	return connection.transaction, nil
}
func (operatorSessionConnection) Close(context.Context) error { return nil }

// The operator session pins search_path before anything runs, and the
// preflight refuses a MeshTransit role, a role without CREATEROLE or
// superuser, and an operator that is a member of a MeshTransit role.
func TestOperatorSessionPinsSearchPathAndRefusesManagedMembership(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		values []any
		want   error
	}{
		"superuser":       {values: []any{180000, "postgres", "postgres", true, false, false}},
		"member":          {values: []any{180000, "postgres", "postgres", true, false, true}, want: ErrOperatorPreflight},
		"no privilege":    {values: []any{180000, "postgres", "postgres", false, false, false}, want: ErrOperatorPreflight},
		"migrator":        {values: []any{180000, "mesh_migrator", "mesh_migrator", false, true, false}, want: ErrOperatorPreflight},
		"session differs": {values: []any{180000, "postgres", "admin", true, false, false}, want: ErrOperatorPreflight},
	} {
		user := test.values[1].(string)
		transaction := &operatorSessionTransaction{preflight: test.values}
		runner := &OperatorRunner{connection: operatorSessionConnection{transaction: transaction},
			options: OperatorOptions{User: user, ConnectTimeout: time.Second, LockTimeout: time.Second, StatementTimeout: 2 * time.Second}}
		err := runner.withTransaction(t.Context(), true, false, func(migrationTransaction) error { return nil })
		if !errors.Is(err, test.want) && (test.want != nil || err != nil) {
			t.Fatalf("%s: %v", name, err)
		}
		if len(transaction.execs) == 0 || !strings.Contains(transaction.execs[0], "'search_path', 'pg_catalog, pg_temp'") {
			t.Fatalf("%s: first statement %v", name, transaction.execs)
		}
	}
}

func TestOperatorReportCountsMembershipsAsIncomplete(t *testing.T) {
	t.Parallel()
	report := operatorFixtureReport(nil, 171)
	if !report.Complete() {
		t.Fatal("a report with every step applied is complete")
	}
	report.Memberships = []string{"mesh_runtime is a member of mesh_share_writer"}
	if report.Complete() {
		t.Fatal("a membership of a MeshTransit role must make verification incomplete")
	}
}
