package postgres

import (
	"context"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/migrations"
)

// operatorSchemas are the schemas whose functions the ownership steps hand
// to owner roles.
var operatorSchemas = []string{"mesh", "mesh_ops", "mesh_audit"}

// operatorGrants lets an operator that is not a superuser (a managed
// service's administrator with CREATEROLE, V1-11 §12) run the ownership
// steps, inside the apply's transaction only:
//
//   - ALTER FUNCTION ... OWNER TO a role needs the operator to act as the
//     function's current owner (the migrator or an owner role) and as the
//     new owner: it joins them WITH INHERIT TRUE, SET TRUE, which ADMIN on
//     roles it created allows;
//   - the new owner needs CREATE on the function's schema (a superuser is
//     exempt): the operator, acting as the migrator that owns the schemas,
//     grants it.
//
// The schema grants are taken back before the after report, the
// memberships after it, both before commit; a failure rolls the
// transaction, and so the grants, back.
type operatorGrants struct {
	superuser bool
	read      bool
	joined    []string
	schemas   map[string][]string // owner role -> schemas granted CREATE
}

func (grants *operatorGrants) superuserOperator(ctx context.Context, transaction migrationTransaction) (bool, error) {
	if grants.read {
		return grants.superuser, nil
	}
	if err := transaction.QueryRow(ctx,
		`SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = CURRENT_USER`).Scan(&grants.superuser); err != nil {
		return false, fmt.Errorf("read operator: %w", err)
	}
	grants.read = true
	return grants.superuser, nil
}

// prepare takes what step needs; nothing for a superuser or a role step.
func (grants *operatorGrants) prepare(ctx context.Context, transaction migrationTransaction, step migrations.OperatorStep) error {
	if step.Kind != migrations.OperatorStepOwnership {
		return nil
	}
	superuser, err := grants.superuserOperator(ctx, transaction)
	if err != nil || superuser {
		return err
	}
	owners := []string{}
	for _, effect := range step.Effects {
		if effect.Kind == migrations.OperatorEffectOwner && !slices.Contains(owners, effect.Role) {
			owners = append(owners, effect.Role)
		}
	}
	if len(owners) == 0 {
		return nil
	}
	if err := grants.join(ctx, transaction, append([]string{"mesh_migrator"}, owners...)); err != nil {
		return err
	}
	for _, owner := range owners {
		if err := grants.schemaCreate(ctx, transaction, owner); err != nil {
			return err
		}
	}
	return nil
}

func (grants *operatorGrants) join(ctx context.Context, transaction migrationTransaction, roles []string) error {
	for _, role := range roles {
		if slices.Contains(grants.joined, role) {
			continue
		}
		if !loginName.MatchString(role) {
			return fmt.Errorf("%w: role %q", ErrOperatorCatalog, role)
		}
		statement := "GRANT " + pgx.Identifier{role}.Sanitize() + " TO CURRENT_USER WITH INHERIT TRUE, SET TRUE"
		if err := transaction.Exec(ctx, statement); err != nil {
			return fmt.Errorf("operator joins %s: %w", role, err)
		}
		grants.joined = append(grants.joined, role)
	}
	return nil
}

func (grants *operatorGrants) schemaCreate(ctx context.Context, transaction migrationTransaction, owner string) error {
	if _, done := grants.schemas[owner]; done {
		return nil
	}
	if grants.schemas == nil {
		grants.schemas = map[string][]string{}
	}
	granted := []string{}
	for _, schema := range operatorSchemas {
		var exists, holds bool
		if err := transaction.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace($1) IS NOT NULL,
    pg_catalog.to_regnamespace($1) IS NOT NULL AND pg_catalog.has_schema_privilege($2, $1, 'CREATE')`,
			schema, owner).Scan(&exists, &holds); err != nil {
			return fmt.Errorf("read CREATE on %s for %s: %w", schema, owner, err)
		}
		if !exists || holds {
			continue
		}
		statement := "GRANT CREATE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + pgx.Identifier{owner}.Sanitize()
		if err := transaction.Exec(ctx, statement); err != nil {
			return fmt.Errorf("grant CREATE on %s to %s: %w", schema, owner, err)
		}
		granted = append(granted, schema)
	}
	grants.schemas[owner] = granted
	return nil
}

// begin lets an operator that is not a superuser read the schema (its
// version, the before and after reports): it joins the migrator, the
// schemas' owner, for the transaction. A superuser needs nothing.
func (grants *operatorGrants) begin(ctx context.Context, transaction migrationTransaction) error {
	superuser, err := grants.superuserOperator(ctx, transaction)
	if err != nil || superuser {
		return err
	}
	// Only when the operator cannot read the schema already: before the
	// first migration there is nothing to read, and an operator given
	// USAGE on mesh_ops and SELECT on its version table (deployment guide)
	// needs nothing more. CASE orders the checks: to_regclass needs USAGE.
	var needs bool
	if err := transaction.QueryRow(ctx, operatorNeedsMigratorSQL).Scan(&needs); err != nil {
		return fmt.Errorf("read operator schema access: %w", err)
	}
	if !needs {
		return nil
	}
	return grants.join(ctx, transaction, []string{"mesh_migrator"})
}

const operatorNeedsMigratorSQL = `SELECT CASE
    WHEN pg_catalog.to_regnamespace('mesh_ops') IS NULL THEN false
    WHEN NOT pg_catalog.has_schema_privilege(CURRENT_USER, 'mesh_ops', 'USAGE') THEN true
    WHEN pg_catalog.to_regclass('mesh_ops.schema_compatibility') IS NULL THEN false
    ELSE NOT pg_catalog.has_table_privilege(CURRENT_USER, 'mesh_ops.schema_compatibility', 'SELECT')
END`

// withoutJoined drops from report the memberships the operator holds only
// because it joined them for this transaction: they end with it, and the
// preflight refuses an operator with a real one.
func (grants *operatorGrants) withoutJoined(report OperatorReport, operator string) OperatorReport {
	if len(grants.joined) == 0 {
		return report
	}
	kept := make([]string, 0, len(report.Memberships))
	for _, membership := range report.Memberships {
		if !slices.ContainsFunc(grants.joined, func(role string) bool {
			return membership == operator+" is a member of "+role
		}) {
			kept = append(kept, membership)
		}
	}
	report.Memberships = kept
	return report
}

// releaseSchemas takes back the schema CREATE prepare gave owner roles:
// before the after report, which requires an owner role to hold nothing
// else.
func (grants *operatorGrants) releaseSchemas(ctx context.Context, transaction migrationTransaction) error {
	for owner, schemas := range grants.schemas {
		for _, schema := range schemas {
			statement := "REVOKE CREATE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " FROM " +
				pgx.Identifier{owner}.Sanitize()
			if err := transaction.Exec(ctx, statement); err != nil {
				return fmt.Errorf("revoke CREATE on %s from %s: %w", schema, owner, err)
			}
		}
	}
	grants.schemas = nil
	return nil
}

// releaseMemberships takes back every membership the operator granted
// itself in a MeshTransit role: those it joined, and the rows
// createrole_self_grant added for the roles the apply created (the
// migration and operator preflights refuse both). It runs after the after
// report (which reads the schema as the migrator), before commit. The
// ADMIN-only grant PostgreSQL records (grantor the bootstrap superuser)
// stays.
func (grants *operatorGrants) releaseMemberships(ctx context.Context, transaction migrationTransaction) error {
	superuser, err := grants.superuserOperator(ctx, transaction)
	if err != nil || superuser {
		return err
	}
	var roles []string
	if err := transaction.QueryRow(ctx, `SELECT COALESCE(pg_catalog.array_agg(granted.rolname::text), ARRAY[]::text[])
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
WHERE member.rolname = CURRENT_USER AND membership.grantor = member.oid AND NOT membership.admin_option
  AND granted.rolname LIKE 'mesh\_%'`).
		Scan(&roles); err != nil {
		return fmt.Errorf("read operator memberships: %w", err)
	}
	for _, role := range roles {
		if !loginName.MatchString(role) {
			return fmt.Errorf("%w: role %q", ErrOperatorCatalog, role)
		}
		statement := "REVOKE " + pgx.Identifier{role}.Sanitize() + " FROM CURRENT_USER GRANTED BY CURRENT_USER"
		if err := transaction.Exec(ctx, statement); err != nil {
			return fmt.Errorf("operator leaves %s: %w", role, err)
		}
	}
	grants.joined = nil
	return nil
}
