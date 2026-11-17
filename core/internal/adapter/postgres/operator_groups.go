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
