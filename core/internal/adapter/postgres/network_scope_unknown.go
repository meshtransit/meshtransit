package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// unknownNetworkScope reports set_network_scope's refusal of a Workspace and
// Network pair that does not exist (23503). Management stores answer it with
// their forbidden error, as for a Network the caller may not read, so a
// Network's existence does not leak to someone outside it (TD-CORE-143).
func unknownNetworkScope(err error) bool {
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	return ok && postgresError.Code == "23503" && postgresError.Message == "network scope is unavailable"
}
