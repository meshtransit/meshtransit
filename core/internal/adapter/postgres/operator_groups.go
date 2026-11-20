package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/migrations"
)

// OperatorGroupResult is what one apply did to one group role.
type OperatorGroupResult struct {
	Name    string `json:"name"`
	Created bool   `json:"created"`
}

// operatorGroupCreateAttributes keep a new group role a pure holder of
// grants: it never logs in and carries no special right.
const operatorGroupCreateAttributes = "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
	"CONNECTION LIMIT -1"

// operatorGroupStateSQL reads what may have drifted on a group role; no row
// means it is missing. A password is not read (pg_roles always shows
// "********") nor cleared: a NOLOGIN role cannot authenticate with it.
const operatorGroupStateSQL = `SELECT role.rolcanlogin, role.rolsuper, role.rolcreatedb, role.rolcreaterole,
    role.rolreplication, role.rolbypassrls, role.rolconnlimit <> -1,
    role.rolconfig IS NOT NULL OR EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting AS setting
        WHERE setting.setrole = role.oid AND setting.setdatabase = 0),
    ARRAY(SELECT database.datname::TEXT FROM pg_catalog.pg_db_role_setting AS setting
        JOIN pg_catalog.pg_database AS database ON database.oid = setting.setdatabase
        WHERE setting.setrole = role.oid ORDER BY 1)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname = $1`

// groupDrift is what changed on an existing group role.
type groupDrift struct {
	login, superuser, createDB, createRole, replication, bypassRLS, connectionLimit bool
	settings                                                                        bool
	// databases holds the databases with settings of their own for the role.
	databases []string
}

// statements returns only the ALTERs that undo the drift, so an operator
// with CREATEROLE only, which may not even name SUPERUSER or REPLICATION,
// applies cleanly on a group that did not change.
func (drift groupDrift) statements(identifier string) []string {
	var attributes []string
	for _, attribute := range []struct {
		drifted bool
		reset   string
	}{
		{drift.login, "NOLOGIN"}, {drift.superuser, "NOSUPERUSER"}, {drift.createDB, "NOCREATEDB"},
		{drift.createRole, "NOCREATEROLE"}, {drift.replication, "NOREPLICATION"},
		{drift.bypassRLS, "NOBYPASSRLS"}, {drift.connectionLimit, "CONNECTION LIMIT -1"},
	} {
		if attribute.drifted {
			attributes = append(attributes, attribute.reset)
		}
	}
	var statements []string
	if len(attributes) != 0 {
		statements = append(statements, "ALTER ROLE "+identifier+" "+strings.Join(attributes, " "))
	}
	if drift.settings {
		statements = append(statements, "ALTER ROLE "+identifier+" RESET ALL")
	}
	for _, database := range drift.databases {
		statements = append(statements, "ALTER ROLE "+identifier+" IN DATABASE "+
			pgx.Identifier{database}.Sanitize()+" RESET ALL")
	}
	return statements
}

// ensureOperatorGroups creates each group role that is missing and resets
// the attributes and settings of one someone changed (role isolation
// design §3.5, release N0). It grants nothing and adds no member: later
// releases do, through migrations, operator steps and the login catalog.
func ensureOperatorGroups(ctx context.Context, transaction migrationTransaction) ([]OperatorGroupResult, error) {
	groups := migrations.OperatorGroupRoles()
	results := make([]OperatorGroupResult, 0, len(groups))
	for _, name := range groups {
		if !loginName.MatchString(name) {
			return nil, fmt.Errorf("%w: group role name %q", ErrOperatorCatalog, name)
		}
		identifier := pgx.Identifier{name}.Sanitize()
		var drift groupDrift
		err := transaction.QueryRow(ctx, operatorGroupStateSQL, name).Scan(&drift.login, &drift.superuser,
			&drift.createDB, &drift.createRole, &drift.replication, &drift.bypassRLS, &drift.connectionLimit,
			&drift.settings, &drift.databases)
		exists := true
		if errors.Is(err, pgx.ErrNoRows) {
			exists = false
		} else if err != nil {
			return nil, fmt.Errorf("read group role %s: %w", name, err)
		}
		statements := drift.statements(identifier)
		if !exists {
			statements = []string{"CREATE ROLE " + identifier + " " + operatorGroupCreateAttributes}
		}
		for _, statement := range statements {
			if err := transaction.Exec(ctx, statement); err != nil {
				return nil, fmt.Errorf("keep group role %s (%s): %w", name, statement, err)
			}
		}
		results = append(results, OperatorGroupResult{Name: name, Created: !exists})
	}
	return results, nil
}

// OperatorMembershipResult is what one apply did to one membership of an
// existing role.
type OperatorMembershipResult struct {
	Member  string `json:"member"`
	Of      string `json:"of"`
	Granted bool   `json:"granted"`
}

// operatorMembershipStateSQL reports whether both roles exist and whether
// the membership is already exactly INHERIT without SET or ADMIN.
const operatorMembershipStateSQL = `SELECT
    EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)
        AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $2),
    EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
        JOIN pg_catalog.pg_roles AS granted_role ON granted_role.oid = membership.roleid
        WHERE member_role.rolname = $1 AND granted_role.rolname = $2
          AND membership.inherit_option AND NOT membership.set_option AND NOT membership.admin_option)`

// ensureOperatorRoleMemberships keeps each membership of an existing role
// (role isolation S2.2: mesh_runtime, the api's login, joins mesh_api_rights)
// as INHERIT without SET or ADMIN. A role that does not exist yet is left
// alone: the database that lacks mesh_runtime serves no api.
func ensureOperatorRoleMemberships(
	ctx context.Context,
	transaction migrationTransaction,
) ([]OperatorMembershipResult, error) {
	memberships := migrations.OperatorRoleMemberships()
	results := make([]OperatorMembershipResult, 0, len(memberships))
	for _, membership := range memberships {
		if !loginName.MatchString(membership.Member) || !loginName.MatchString(membership.Of) {
			return nil, fmt.Errorf("%w: membership %s of %s", ErrOperatorCatalog, membership.Of, membership.Member)
		}
		var present, held bool
		if err := transaction.QueryRow(ctx, operatorMembershipStateSQL, membership.Member, membership.Of).Scan(
			&present, &held); err != nil {
			return nil, fmt.Errorf("read membership %s of %s: %w", membership.Of, membership.Member, err)
		}
		result := OperatorMembershipResult{Member: membership.Member, Of: membership.Of}
		if present && !held {
			member := pgx.Identifier{membership.Member}.Sanitize()
			granted := pgx.Identifier{membership.Of}.Sanitize()
			for _, statement := range []string{
				"GRANT " + granted + " TO " + member + " WITH INHERIT TRUE, SET FALSE",
				"REVOKE ADMIN OPTION FOR " + granted + " FROM " + member,
			} {
				if err := transaction.Exec(ctx, statement); err != nil {
					return nil, fmt.Errorf("grant %s to %s: %w", membership.Of, membership.Member, err)
				}
			}
			result.Granted = true
		}
		if present {
			results = append(results, result)
		}
	}
	return results, nil
}

// ensureOperatorOwnerRole runs a role step (a NOLOGIN owner role) without
// its canonical block: that block resets an existing role with ALTER ROLE
// ... NOSUPERUSER ..., which PostgreSQL refuses to an operator that is not
// a superuser even when nothing differs (a managed service's administrator,
// V1-11 §12). The role is created when missing; otherwise only what drifted
// is undone, as for the group roles. The step's requirement check is the
// same either way.
func ensureOperatorOwnerRole(ctx context.Context, transaction migrationTransaction, name string) error {
	if !loginName.MatchString(name) {
		return fmt.Errorf("%w: owner role name %q", ErrOperatorCatalog, name)
	}
	identifier := pgx.Identifier{name}.Sanitize()
	var drift groupDrift
	err := transaction.QueryRow(ctx, operatorGroupStateSQL, name).Scan(&drift.login, &drift.superuser,
		&drift.createDB, &drift.createRole, &drift.replication, &drift.bypassRLS, &drift.connectionLimit,
		&drift.settings, &drift.databases)
	statements := drift.statements(identifier)
	if errors.Is(err, pgx.ErrNoRows) {
		statements = []string{"CREATE ROLE " + identifier + " " + operatorGroupCreateAttributes}
	} else if err != nil {
		return fmt.Errorf("read owner role %s: %w", name, err)
	}
	for _, statement := range statements {
		if err := transaction.Exec(ctx, statement); err != nil {
			return fmt.Errorf("keep owner role %s: %w", name, err)
		}
	}
	return nil
}
