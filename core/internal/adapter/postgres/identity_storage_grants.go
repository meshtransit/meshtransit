package postgres

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
)

// ErrIdentityStorageGrants reports a failed grant of the identity broker's
// database to its runtime role.
var ErrIdentityStorageGrants = errors.New("grant identity broker storage")

var identityRoleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// GrantIdentityRuntime gives the identity broker's runtime role data access
// (no DDL) to the tables and sequences the broker's migration created, as
// the broker database's owner, the migration identity in options. The broker
// runtime never migrates, so it never needs more.
func GrantIdentityRuntime(ctx context.Context, options MigrationOptions, runtimeRole string) (resultErr error) {
	if ctx == nil || !identityRoleName.MatchString(runtimeRole) || !identityRoleName.MatchString(options.Database) {
		return ErrInvalidMigrationOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return errors.Join(ErrIdentityStorageGrants, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return errors.Join(ErrIdentityStorageGrants, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(options, password, caPEM)
	if err != nil {
		return err
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-setup"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return errors.Join(ErrIdentityStorageGrants, err)
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(closeContext))
	}()
	role := pgx.Identifier{runtimeRole}.Sanitize()
	database := pgx.Identifier{options.Database}.Sanitize()
	return pgx.BeginFunc(ctx, connection, func(tx pgx.Tx) error {
		for _, statement := range []string{
			"GRANT CONNECT ON DATABASE " + database + " TO " + role,
			"GRANT USAGE ON SCHEMA public TO " + role,
			"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + role,
			"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO " + role,
		} {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return errors.Join(ErrIdentityStorageGrants, err)
			}
		}
		return nil
	})
}
