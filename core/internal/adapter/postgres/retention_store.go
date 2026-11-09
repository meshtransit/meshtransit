package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/retention"
)

// ErrInvalidRetentionStore reports unsafe construction, input or answers.
var ErrInvalidRetentionStore = errors.New("invalid postgres retention store")

const (
	pruneIdempotencySQL = `SELECT mesh_ops.prune_idempotency_records_v1($1::INTEGER, $2::INTEGER)`
	pruneOutboxSQL      = `SELECT mesh_ops.prune_outbox_events_v1($1::INTEGER, $2::INTEGER, $3::INTEGER)::TEXT`
	dropAuditSQL        = `SELECT mesh_ops.drop_audit_event_partitions_v1($1::INTEGER)`
	pruneAuditSQL       = `SELECT mesh_ops.prune_audit_rows_v1($1::INTEGER, $2::INTEGER)::TEXT`
	foldSummaryMarksSQL = `SELECT mesh_ops.fold_network_summary_marks_v1($1::INTEGER)`
	// maximumRetentionBatch is what the definer functions accept (schema 274).
	maximumRetentionBatch = 5000
)

// RetentionStore removes expired rows through the worker pool (schema 274):
// each call is one definer function's transaction, which takes its own
// short lock timeout and records what it removed.
type RetentionStore struct{ database outboxDatabase }

var _ retention.Store = (*RetentionStore)(nil)

// NewRetentionStore rejects non-worker pools before any effect.
func NewRetentionStore(pool *Pool) (*RetentionStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidRetentionStore
	}
	return &RetentionStore{database: pool.outboxDatabase}, nil
}

// retentionFailure keeps the cause and gives it the domain's class: a lock
// not taken in time is busy; a function missing (an older schema) or
// refused (operator step 274 not applied) is not ready.
func retentionFailure(what string, err error) error {
	class := error(nil)
	if postgresError, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch postgresError.Code {
		case "55P03":
			class = retention.ErrBusy
		case "42883", "42501", "23514":
			class = retention.ErrNotReady
		}
	}
	if class == nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s: %w", what, errors.Join(class, err))
}

func (store *RetentionStore) usable(ctx context.Context, limit int) bool {
	return ctx != nil && store != nil && store.database != nil && limit >= 1 && limit <= maximumRetentionBatch
}

// FoldSummaryMarks moves up to limit Network summary change marks into
// their queue, in its own transaction; 0 when another worker is folding.
func (store *RetentionStore) FoldSummaryMarks(ctx context.Context, limit int) (int, error) {
	if !store.usable(ctx, limit) {
		return 0, ErrInvalidRetentionStore
	}
	var folded int
	if err := store.database.QueryRow(ctx, foldSummaryMarksSQL, limit).Scan(&folded); err != nil {
		return 0, retentionFailure("fold summary marks", err)
	}
	if folded < 0 || folded > limit {
		return 0, ErrInvalidRetentionStore
	}
	return folded, nil
}

// PruneIdempotency removes up to limit records that expired more than grace ago.
func (store *RetentionStore) PruneIdempotency(ctx context.Context, grace time.Duration, limit int) (int, error) {
	if !store.usable(ctx, limit) || grace < time.Hour || grace > 30*24*time.Hour {
		return 0, ErrInvalidRetentionStore
	}
	seconds := int(math.Round(grace.Seconds()))
	var removed int
	if err := store.database.QueryRow(ctx, pruneIdempotencySQL, seconds, limit).Scan(&removed); err != nil {
		return 0, retentionFailure("prune idempotency records", err)
	}
	if removed < 0 || removed > limit {
		return 0, ErrInvalidRetentionStore
	}
	return removed, nil
}

// PruneOutbox removes up to limit finished outbox events and their attempts.
func (store *RetentionStore) PruneOutbox(ctx context.Context, deliveredDays, terminalDays, limit int) (
	retention.OutboxRemoved, error,
) {
	if !store.usable(ctx, limit) || deliveredDays < 1 || terminalDays < deliveredDays || terminalDays > 365 {
		return retention.OutboxRemoved{}, ErrInvalidRetentionStore
	}
	var answer string
	if err := store.database.QueryRow(ctx, pruneOutboxSQL, deliveredDays, terminalDays, limit).Scan(
		&answer); err != nil {
		return retention.OutboxRemoved{}, retentionFailure("prune outbox events", err)
	}
	var removed struct {
		Events   *int `json:"events"`
		Attempts *int `json:"attempts"`
	}
	if err := json.Unmarshal([]byte(answer), &removed); err != nil || removed.Events == nil ||
		removed.Attempts == nil || *removed.Events < 0 || *removed.Events > limit || *removed.Attempts < 0 {
		return retention.OutboxRemoved{}, ErrInvalidRetentionStore
	}
	return retention.OutboxRemoved{Events: *removed.Events, Attempts: *removed.Attempts}, nil
}

// DropAuditPartitions drops the whole Activity months past keepMonths.
func (store *RetentionStore) DropAuditPartitions(ctx context.Context, keepMonths int) ([]string, error) {
	if !store.usable(ctx, 1) || keepMonths < 1 || keepMonths > 120 {
		return nil, ErrInvalidRetentionStore
	}
	var dropped []string
	if err := store.database.QueryRow(ctx, dropAuditSQL, keepMonths).Scan(&dropped); err != nil {
		return nil, retentionFailure("drop audit partitions", err)
	}
	return dropped, nil
}

// PruneAudit removes up to limit rows of each kind the dropped months leave
// behind.
func (store *RetentionStore) PruneAudit(ctx context.Context, keepMonths, limit int) (retention.AuditRemoved, error) {
	if !store.usable(ctx, limit) || keepMonths < 1 || keepMonths > 120 {
		return retention.AuditRemoved{}, ErrInvalidRetentionStore
	}
	var answer string
	if err := store.database.QueryRow(ctx, pruneAuditSQL, keepMonths, limit).Scan(&answer); err != nil {
		return retention.AuditRemoved{}, retentionFailure("prune audit rows", err)
	}
	var removed struct {
		Defaults   *int `json:"defaults"`
		Identities *int `json:"identities"`
		Mutations  *int `json:"mutations"`
	}
	if err := json.Unmarshal([]byte(answer), &removed); err != nil || removed.Defaults == nil ||
		removed.Identities == nil || removed.Mutations == nil {
		return retention.AuditRemoved{}, ErrInvalidRetentionStore
	}
	for _, count := range []int{*removed.Defaults, *removed.Identities, *removed.Mutations} {
		if count < 0 || count > limit {
			return retention.AuditRemoved{}, ErrInvalidRetentionStore
		}
	}
	return retention.AuditRemoved{Defaults: *removed.Defaults, Identities: *removed.Identities,
		Mutations: *removed.Mutations}, nil
}
