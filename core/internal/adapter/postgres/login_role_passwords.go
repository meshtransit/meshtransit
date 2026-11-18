package postgres

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
)

// ErrLoginRolePasswords reports a failed password reconciliation.
var ErrLoginRolePasswords = errors.New("set login role passwords")

var scramVerifierText = regexp.MustCompile(`^SCRAM-SHA-256\$[0-9]{4,7}:[A-Za-z0-9+/=]{4,64}\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}$`)

// RoleVerifier is one existing login role and its new SCRAM verifier.
type RoleVerifier struct {
	Role     string
	Verifier string
}

// SetLoginRolePasswords stores each role's SCRAM verifier, as the bundled
// database's superuser (options), in one transaction. Only existing roles
// with the exact names given change; the verifier text is checked before it
// reaches SQL, and the password itself never does. It then reloads the
// server configuration, so a login setup added to pg_hba.conf may connect.
func SetLoginRolePasswords(ctx context.Context, options MigrationOptions, roles []RoleVerifier) (resultErr error) {
	if ctx == nil || len(roles) == 0 {
		return ErrInvalidMigrationOptions
	}
	for _, role := range roles {
		if !identityRoleName.MatchString(role.Role) || !scramVerifierText.MatchString(role.Verifier) {
			return ErrInvalidMigrationOptions
		}
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return errors.Join(ErrLoginRolePasswords, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return errors.Join(ErrLoginRolePasswords, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(options, password, caPEM)
	if err != nil {
		return err
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-setup"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return errors.Join(ErrLoginRolePasswords, err)
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(closeContext))
	}()
	return pgx.BeginFunc(ctx, connection, func(tx pgx.Tx) error {
		for _, role := range roles {
			statement := "ALTER ROLE " + pgx.Identifier{role.Role}.Sanitize() + " PASSWORD '" + role.Verifier + "'"
			if _, err := tx.Exec(ctx, statement); err != nil {
				return errors.Join(ErrLoginRolePasswords, err)
			}
		}
		// pg_hba.conf is a file setup renders; Postgres reads it again only
		// on reload, and a new release may add a login to it (mesh_all, role
		// isolation S2.2).
		var reloaded bool
		if err := tx.QueryRow(ctx, "SELECT pg_catalog.pg_reload_conf()").Scan(&reloaded); err != nil || !reloaded {
			return errors.Join(ErrLoginRolePasswords, errors.New("reload PostgreSQL configuration"), err)
		}
		return nil
	})
}
