package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/migrations"
)

// OperatorStepState is the stable, operator-facing state of one step.
type OperatorStepState string

const (
	// OperatorStepApplied means every fact the step sets holds.
	OperatorStepApplied OperatorStepState = "applied"
	// OperatorStepPending means the step's migration is applied but at least
	// one fact it sets does not hold.
	OperatorStepPending OperatorStepState = "pending"
	// OperatorStepAwaitingMigration means the ownership step's migration is
	// not applied yet, so the step cannot run.
	OperatorStepAwaitingMigration OperatorStepState = "awaiting_migration"
)

// OperatorWaitReason says why a step that is not applied does not run now.
type OperatorWaitReason string

const (
	// OperatorWaitMigration means its migration is not applied yet.
	OperatorWaitMigration OperatorWaitReason = "awaiting_migration"
	// OperatorWaitRollout means it runs only once no replica of the previous
	// release is left, which the operator confirms with AfterRollout.
	OperatorWaitRollout OperatorWaitReason = "after_rollout"
	// OperatorWaitEarlierStep means an earlier step waits, and steps run in order.
	OperatorWaitEarlierStep OperatorWaitReason = "after_earlier_step"
	// OperatorWaitThrough means its migration is newer than the requested Through.
	OperatorWaitThrough OperatorWaitReason = "beyond_through"
)

var (
	// ErrOperatorStepRefused reports a requested step that cannot run.
	ErrOperatorStepRefused = errors.New("operator step refused")
	// ErrOperatorStepUnverified reports that, after running, a step's facts
	// did not hold or an applied step stopped holding; nothing is committed.
	ErrOperatorStepUnverified = errors.New("operator step did not verify")
	// ErrOperatorCatalog reports an embedded catalog the binary cannot use.
	ErrOperatorCatalog = errors.New("invalid operator step catalog")
)

// OperatorStepRefusedError names the step a request cannot run and why.
type OperatorStepRefusedError struct {
	Step   string
	Reason OperatorWaitReason
}

func (err *OperatorStepRefusedError) Error() string {
	return fmt.Sprintf("operator step %s refused: %s", err.Step, err.Reason)
}

// Unwrap lets errors.Is match ErrOperatorStepRefused.
func (*OperatorStepRefusedError) Unwrap() error { return ErrOperatorStepRefused }

// OperatorStepStatus is one catalog step and what PostgreSQL shows of it.
type OperatorStepStatus struct {
	Name         string
	Version      int64
	Kind         string
	AfterRollout bool
	State        OperatorStepState
	// Missing describes each fact of a pending step that does not hold.
	Missing []string
}

// OperatorReport is the state of every catalog step on one database.
type OperatorReport struct {
	CurrentSchemaVersion int64
	Steps                []OperatorStepStatus
	// Memberships lists each role membership a MeshTransit role takes part
	// in, as member or as granted role; there must be none.
	Memberships []string
}

// Complete reports that no step of an applied migration is pending and no
// MeshTransit role takes part in a membership.
func (report OperatorReport) Complete() bool {
	return len(report.Pending()) == 0 && len(report.Memberships) == 0
}

// Pending returns the steps whose migration is applied and that do not hold.
func (report OperatorReport) Pending() []OperatorStepStatus {
	pending := []OperatorStepStatus{}
	for _, step := range report.Steps {
		if step.State == OperatorStepPending {
			pending = append(pending, step)
		}
	}
	return pending
}

func (report OperatorReport) state(name string) OperatorStepState {
	for _, step := range report.Steps {
		if step.Name == name {
			return step.State
		}
	}
	return ""
}

// OperatorApplyOptions bounds one apply.
type OperatorApplyOptions struct {
	// DryRun runs and verifies the steps, then rolls everything back.
	DryRun bool
	// AfterRollout confirms that no replica of the previous release is left,
	// so the steps that wait for it may run.
	AfterRollout bool
	// Through, when positive, is the newest migration whose steps may run;
	// a step of a migration up to Through that is not applied is refused.
	Through int64
}

// OperatorWaiting is one step an apply left for later.
type OperatorWaiting struct {
	Step   string
	Reason OperatorWaitReason
}

// OperatorApplyResult reports one apply.
type OperatorApplyResult struct {
	DryRun bool
	// Applied lists the pending steps that ran, in order.
	Applied []string
	// Replayed lists applied steps that ran again after an earlier pending
	// one, so that their facts stay the last word.
	Replayed []string
	Waiting  []OperatorWaiting
	// Report is the state after the steps ran (for a dry run, as it was
	// inside the transaction before the rollback).
	Report OperatorReport
}

type operatorPlan struct {
	Run     []string
	Waiting []OperatorWaiting
}

// dueOperatorSteps returns the steps that can hold on a schema: every role
// step and the ownership steps of applied migrations.
func dueOperatorSteps(steps []migrations.OperatorStep, schemaVersion int64) []migrations.OperatorStep {
	due := make([]migrations.OperatorStep, 0, len(steps))
	for _, step := range steps {
		if step.Kind == migrations.OperatorStepRole || step.Version <= schemaVersion {
			due = append(due, step)
		}
	}
	return due
}

// planOperatorSteps chooses, in catalog order, the steps an apply runs: from
// the earliest pending step on, every due step runs again (each is
// idempotent), so an earlier step never overrides a later one. A pending step
// that waits for the rollout stops the plan there, except for role steps:
// they only create owner roles, which the next migration may need.
func planOperatorSteps(
	steps []migrations.OperatorStep,
	report OperatorReport,
	options OperatorApplyOptions,
) (operatorPlan, error) {
	plan := operatorPlan{}
	for _, step := range steps {
		if options.Through > 0 && step.Version <= options.Through &&
			report.state(step.Name) == OperatorStepAwaitingMigration {
			return operatorPlan{}, &OperatorStepRefusedError{Step: step.Name, Reason: OperatorWaitMigration}
		}
	}
	started, held := false, false
	for _, step := range steps {
		state := report.state(step.Name)
		switch {
		case state == "":
			return operatorPlan{}, fmt.Errorf("%w: %s missing from the report", ErrOperatorCatalog, step.Name)
		case options.Through > 0 && step.Version > options.Through:
			if state != OperatorStepApplied {
				plan.Waiting = append(plan.Waiting, OperatorWaiting{Step: step.Name, Reason: OperatorWaitThrough})
			}
		case state == OperatorStepAwaitingMigration:
			plan.Waiting = append(plan.Waiting, OperatorWaiting{Step: step.Name, Reason: OperatorWaitMigration})
		case held && step.Kind != migrations.OperatorStepRole && state != OperatorStepApplied:
			// Applied steps after a held one still run again below, so
			// an earlier step that ran never overrides them.
			plan.Waiting = append(plan.Waiting, OperatorWaiting{Step: step.Name, Reason: OperatorWaitEarlierStep})
		case state == OperatorStepPending && step.AfterRollout && !options.AfterRollout:
			plan.Waiting = append(plan.Waiting, OperatorWaiting{Step: step.Name, Reason: OperatorWaitRollout})
			held = true
		case state == OperatorStepPending || started:
			started = true
			plan.Run = append(plan.Run, step.Name)
		}
	}
	return plan, nil
}

// verifyOperatorApply requires every step that ran to hold afterwards and no
// step that held before to stop holding.
func verifyOperatorApply(before, after OperatorReport, run []string) error {
	for _, name := range run {
		if after.state(name) != OperatorStepApplied {
			return fmt.Errorf("%w: %s", ErrOperatorStepUnverified, name)
		}
	}
	for _, step := range before.Steps {
		if step.State == OperatorStepApplied && after.state(step.Name) != OperatorStepApplied {
			return fmt.Errorf("%w: %s no longer holds", ErrOperatorStepUnverified, step.Name)
		}
	}
	return nil
}

// operatorRequirementsSQL evaluates every requirement in one statement and
// returns whether each holds, in order. Any role can read these catalogs, so
// the runtime and worker roles run it too.
const operatorRequirementsSQL = `SELECT COALESCE(pg_catalog.array_agg(
    CASE requirement.kind
    WHEN 'role' THEN EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = requirement.role_name
          AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolcreatedb
          AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls)
    WHEN 'owner' THEN EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = routine.proowner
        WHERE routine.oid = pg_catalog.to_regprocedure(requirement.routine_signature)
          AND owner.rolname = requirement.role_name)
    ELSE (
        EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS routine
            WHERE routine.oid = pg_catalog.to_regprocedure(requirement.routine_signature))
        AND EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc AS routine
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(routine.proacl, pg_catalog.acldefault('f', routine.proowner))) AS grant_entry
            WHERE routine.oid = pg_catalog.to_regprocedure(requirement.routine_signature)
              AND grant_entry.privilege_type = 'EXECUTE'
              AND grant_entry.grantee = CASE WHEN requirement.role_name = 'public' THEN 0::OID
                  ELSE (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = requirement.role_name) END
        ) = (requirement.kind = 'execute')
        -- A revoked role must not reach the function another way either,
        -- through PUBLIC or a membership.
        AND (requirement.kind = 'execute' OR requirement.role_name = 'public'
            OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS role WHERE role.rolname = requirement.role_name)
            OR NOT pg_catalog.has_function_privilege(requirement.role_name,
                pg_catalog.to_regprocedure(requirement.routine_signature), 'EXECUTE')))
    END
    ORDER BY requirement.ordinal), ARRAY[]::BOOLEAN[])
FROM ROWS FROM (pg_catalog.unnest($1::TEXT[]), pg_catalog.unnest($2::TEXT[]), pg_catalog.unnest($3::TEXT[]))
    WITH ORDINALITY AS requirement(kind, routine_signature, role_name, ordinal)`

// operatorMembershipsSQL lists every membership a MeshTransit role ($1)
// takes part in. MeshTransit roles are never members of another role. A
// grant that carries neither INHERIT nor SET (PostgreSQL 16), such as the
// ADMIN-only grant a CREATEROLE role keeps on each role it creates, gives no
// privilege and is not listed.
const operatorMembershipsSQL = `SELECT COALESCE(pg_catalog.array_agg(
    member_role.rolname || ' is a member of ' || granted_role.rolname
    ORDER BY member_role.rolname, granted_role.rolname), ARRAY[]::TEXT[])
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
JOIN pg_catalog.pg_roles AS granted_role ON granted_role.oid = membership.roleid
WHERE (membership.inherit_option OR membership.set_option)
  AND (member_role.rolname = ANY($1::TEXT[]) OR granted_role.rolname = ANY($1::TEXT[]))`

const operatorSchemaPresentSQL = `SELECT pg_catalog.to_regclass('mesh_ops.schema_compatibility') IS NOT NULL`

const operatorSchemaVersionSQL = `SELECT current_schema_version, migration_state
FROM mesh_ops.schema_compatibility
WHERE singleton = TRUE`

// operatorQueryRow runs one single-row query on a pool, a connection or a
// transaction.
type operatorQueryRow func(context.Context, string, ...any) migrationRow

// readOperatorReport evaluates the catalog against the database for a known
// schema version.
func readOperatorReport(
	ctx context.Context,
	queryRow operatorQueryRow,
	schemaVersion int64,
) (OperatorReport, error) {
	steps, err := migrations.OperatorSteps()
	if err != nil {
		return OperatorReport{}, errors.Join(ErrOperatorCatalog, err)
	}
	requirements := migrations.OperatorRequirements(dueOperatorSteps(steps, schemaVersion))
	kinds := make([]string, len(requirements))
	functions := make([]string, len(requirements))
	roles := make([]string, len(requirements))
	for index, requirement := range requirements {
		kinds[index] = string(requirement.Effect.Kind)
		functions[index] = requirement.Effect.Function
		roles[index] = requirement.Effect.Role
	}
	var satisfied []bool
	if err := queryRow(ctx, operatorRequirementsSQL, kinds, functions, roles).Scan(&satisfied); err != nil {
		return OperatorReport{}, fmt.Errorf("read operator step state: %w", err)
	}
	report, err := summarizeOperatorSteps(steps, requirements, satisfied, schemaVersion)
	if err != nil {
		return OperatorReport{}, err
	}
	managed, err := migrations.OperatorManagedRoles()
	if err != nil {
		return OperatorReport{}, errors.Join(ErrOperatorCatalog, err)
	}
	if err := queryRow(ctx, operatorMembershipsSQL, managed).Scan(&report.Memberships); err != nil {
		return OperatorReport{}, fmt.Errorf("read role memberships: %w", err)
	}
	return report, nil
}

// readOperatorSchemaVersion returns the applied schema version, 0 on a
// database no migration ran on, and refuses a dirty migration state.
func readOperatorSchemaVersion(ctx context.Context, queryRow operatorQueryRow) (int64, error) {
	var present bool
	if err := queryRow(ctx, operatorSchemaPresentSQL).Scan(&present); err != nil {
		return 0, fmt.Errorf("read schema state: %w", err)
	}
	if !present {
		return 0, nil
	}
	var version int64
	var state string
	if err := queryRow(ctx, operatorSchemaVersionSQL).Scan(&version, &state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("read schema state: %w", err)
	}
	if state != string(MigrationStateClean) || version < 0 {
		return 0, fmt.Errorf("%w: migration state is not clean", ErrMigrationState)
	}
	return version, nil
}

func summarizeOperatorSteps(
	steps []migrations.OperatorStep,
	requirements []migrations.OperatorRequirement,
	satisfied []bool,
	schemaVersion int64,
) (OperatorReport, error) {
	if len(satisfied) != len(requirements) {
		return OperatorReport{}, fmt.Errorf("%w: %d results for %d requirements", ErrOperatorCatalog,
			len(satisfied), len(requirements))
	}
	missing := map[string][]string{}
	for index, requirement := range requirements {
		if !satisfied[index] {
			missing[requirement.Step] = append(missing[requirement.Step], describeOperatorRequirement(requirement.Effect))
		}
	}
	report := OperatorReport{CurrentSchemaVersion: schemaVersion, Steps: make([]OperatorStepStatus, 0, len(steps))}
	for _, step := range steps {
		status := OperatorStepStatus{Name: step.Name, Version: step.Version, Kind: string(step.Kind),
			AfterRollout: step.AfterRollout, State: OperatorStepApplied}
		switch {
		case step.Kind == migrations.OperatorStepOwnership && step.Version > schemaVersion:
			status.State = OperatorStepAwaitingMigration
		case len(missing[step.Name]) != 0:
			status.State = OperatorStepPending
			status.Missing = slices.Clone(missing[step.Name])
		}
		report.Steps = append(report.Steps, status)
	}
	return report, nil
}

func describeOperatorRequirement(effect migrations.OperatorEffect) string {
	switch effect.Kind {
	case migrations.OperatorEffectRole:
		return "role " + effect.Role + " is missing or not NOLOGIN without other privileges"
	case migrations.OperatorEffectOwner:
		return "owner of " + effect.Function + " is not " + effect.Role
	case migrations.OperatorEffectExecute:
		return effect.Role + " lacks EXECUTE on " + effect.Function
	default:
		return effect.Role + " still has EXECUTE on " + effect.Function
	}
}
