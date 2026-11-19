package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// OperatorConnectionLimitResult is the connection limit an apply set on a
// serving login, and the one it had before.
type OperatorConnectionLimitResult struct {
	Name     string `json:"name"`
	Limit    int    `json:"limit"`
	Previous int    `json:"previous"`
}

// ErrOperatorConnectionLimit reports a connection limit for a role that is
// missing or cannot log in.
var ErrOperatorConnectionLimit = errors.New("operator connection limit is invalid")

const operatorConnectionLimitSQL = `SELECT role.rolconnlimit FROM pg_catalog.pg_roles AS role
WHERE role.rolname = $1 AND role.rolcanlogin`

// ensureOperatorConnectionLimits sets, in name order, the most connections
// each named serving login may hold (TD-CORE-139): PostgreSQL refuses the
// next one, so pods scaled past the budget cannot take the database's
// memory. A limited login must exist and log in; -1 removes a limit, and is
// nothing to do for a login that does not exist.
func ensureOperatorConnectionLimits(ctx context.Context, transaction migrationTransaction,
	limits map[string]int,
) ([]OperatorConnectionLimitResult, error) {
	names := make([]string, 0, len(limits))
	for name := range limits {
		names = append(names, name)
	}
	slices.Sort(names)
	results := make([]OperatorConnectionLimitResult, 0, len(names))
	for _, name := range names {
		limit := limits[name]
		if !loginName.MatchString(name) || (limit < 1 && limit != -1) {
			return nil, fmt.Errorf("%w: %q", ErrOperatorConnectionLimit, name)
		}
		var previous int
		err := transaction.QueryRow(ctx, operatorConnectionLimitSQL, name).Scan(&previous)
		if errors.Is(err, pgx.ErrNoRows) {
			if limit == -1 {
				continue
			}
			return nil, fmt.Errorf("%w: login %s does not exist", ErrOperatorConnectionLimit, name)
		}
		if err != nil {
			return nil, fmt.Errorf("read connection limit of %s: %w", name, err)
		}
		// Only a change needs ALTER ROLE, and with it the right to alter the
		// login: an unchanged limit asks nothing of the operator.
		if previous != limit {
			if err := transaction.Exec(ctx, "ALTER ROLE "+pgx.Identifier{name}.Sanitize()+
				" CONNECTION LIMIT "+strconv.Itoa(limit)); err != nil {
				return nil, fmt.Errorf("set connection limit of %s: %w", name, err)
			}
		}
		results = append(results, OperatorConnectionLimitResult{Name: name, Limit: limit, Previous: previous})
	}
	return results, nil
}
