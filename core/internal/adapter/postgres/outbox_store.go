package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/network/revisionworker"
)

const (
	maxOutboxBatchSize   = 256
	maxOutboxLease       = 5 * time.Minute
	maxOutboxRetryDelay  = 24 * time.Hour
	outboxRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidOutboxStore indicates missing dependencies or unsafe inputs.
	ErrInvalidOutboxStore = errors.New("invalid postgres outbox store")
	// ErrReadOutboxBacklog classifies failure to observe pending durable work.
	ErrReadOutboxBacklog = errors.New("read postgres outbox backlog")
	// ErrClaimOutbox classifies failure to lease pending durable work.
	ErrClaimOutbox = errors.New("claim postgres outbox work")
	// ErrLoadOutboxRevision classifies failure to reconcile authoritative state.
	ErrLoadOutboxRevision = errors.New("load postgres outbox revision")
	// ErrFinishOutbox classifies failure to persist a delivery outcome.
	ErrFinishOutbox = errors.New("finish postgres outbox work")
	// ErrOutboxClaimLost indicates that the lease expired or was fenced out.
	ErrOutboxClaimLost = errors.New("postgres outbox claim lost")
	// ErrOutboxRevisionRegressed indicates impossible durable revision ordering.
	ErrOutboxRevisionRegressed = errors.New("postgres outbox revision regressed")
)

// OutboxStore claims and completes durable Network-revision delivery work.
// It holds no goroutine and every operation is bounded by the caller context.
type OutboxStore struct {
	database outboxDatabase
	newToken func() (string, error)
	metrics  *postgresPoolMetrics
}

// ReadNetworkRevisionBacklog reports only work currently eligible for claim.
// It does not expose event identifiers or payload metadata.
func (store *OutboxStore) ReadNetworkRevisionBacklog(
	ctx context.Context,
) (backlog revisionworker.Backlog, resultErr error) {
	if ctx == nil || store == nil || store.database == nil {
		return revisionworker.Backlog{}, ErrInvalidOutboxStore
	}
	startedAt := time.Now()
	defer func() {
		store.metrics.observeOperation(postgresOperationOutboxBacklog, time.Since(startedAt), resultErr)
	}()
	var events, oldestAgeMilliseconds int64
	if err := store.database.QueryRow(ctx, readNetworkRevisionBacklogSQL).Scan(
		&events,
		&oldestAgeMilliseconds,
	); err != nil {
		return revisionworker.Backlog{}, errors.Join(ErrReadOutboxBacklog, err)
	}
	backlog, err := revisionworker.NewBacklog(
		events,
		time.Duration(oldestAgeMilliseconds)*time.Millisecond,
	)
	if err != nil {
		return revisionworker.Backlog{}, errors.Join(ErrReadOutboxBacklog, err)
	}
	return backlog, nil
}

// NewOutboxStore constructs the worker adapter from a worker-authenticated pool.
func NewOutboxStore(pool *Pool) (*OutboxStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidOutboxStore
	}
	return newOutboxStore(pool.outboxDatabase, randomClaimToken, pool.metrics)
}

func newOutboxStore(
	database outboxDatabase,
	newToken func() (string, error),
	metrics *postgresPoolMetrics,
) (*OutboxStore, error) {
	if database == nil || newToken == nil {
		return nil, ErrInvalidOutboxStore
	}
	return &OutboxStore{database: database, newToken: newToken, metrics: metrics}, nil
}

// ClaimNetworkRevisions leases a bounded ordered batch using SKIP LOCKED.
func (store *OutboxStore) ClaimNetworkRevisions(
	ctx context.Context,
	workerID string,
	limit int,
	lease time.Duration,
) (claims []network.RevisionClaim, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || store.newToken == nil ||
		!validOutboxWorkerID(workerID) || limit <= 0 || limit > maxOutboxBatchSize ||
		lease < time.Millisecond || lease > maxOutboxLease {
		return nil, ErrInvalidOutboxStore
	}
	token, err := store.newToken()
	if err != nil {
		return nil, errors.Join(ErrClaimOutbox, fmt.Errorf("generate claim token: %w", err))
	}
	startedAt := time.Now()
	defer func() {
		store.metrics.observeOperation(postgresOperationOutboxClaim, time.Since(startedAt), resultErr)
	}()

	rows, err := store.database.Query(
		ctx,
		claimNetworkRevisionsSQL,
		limit,
		token,
		workerID,
		lease.Milliseconds(),
	)
	if err != nil {
		return nil, errors.Join(ErrClaimOutbox, err)
	}
	if rows == nil {
		return nil, ErrClaimOutbox
	}
	defer rows.Close()

	claims = make([]network.RevisionClaim, 0, limit)
	for rows.Next() {
		var eventID, workspaceID, networkID, recordedRevision int64
		var attempt int
		var claimedAt time.Time
		if err := rows.Scan(
			&eventID,
			&workspaceID,
			&networkID,
			&recordedRevision,
			&attempt,
			&claimedAt,
		); err != nil {
			return nil, errors.Join(ErrClaimOutbox, fmt.Errorf("scan claim: %w", err))
		}
		claim, err := network.NewRevisionClaim(
			eventID,
			workspaceID,
			networkID,
			recordedRevision,
			token,
			workerID,
			attempt,
			claimedAt,
		)
		if err != nil {
			return nil, errors.Join(ErrClaimOutbox, err)
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrClaimOutbox, fmt.Errorf("iterate claims: %w", err))
	}
	return claims, nil
}

// LoadNetworkRevision reads the current authoritative revision under the exact
// Workspace and Network RLS scope carried by a valid claim.
func (store *OutboxStore) LoadNetworkRevision(
	ctx context.Context,
	claim network.RevisionClaim,
) (revision network.RevisionAdvanced, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !claim.IsValid() {
		return network.RevisionAdvanced{}, ErrInvalidOutboxStore
	}
	startedAt := time.Now()
	defer func() {
		store.metrics.observeOperation(postgresOperationOutboxLoadRevision, time.Since(startedAt), resultErr)
	}()
	transaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return network.RevisionAdvanced{}, errors.Join(ErrLoadOutboxRevision, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()

	if err := transaction.Exec(
		ctx,
		setOutboxScopeSQL,
		fmt.Sprintf("%d", claim.WorkspaceID()),
		fmt.Sprintf("%d", claim.NetworkID()),
	); err != nil {
		return network.RevisionAdvanced{}, errors.Join(ErrLoadOutboxRevision, fmt.Errorf("set exact scope: %w", err))
	}
	var networkPublicID string
	var currentRevision int64
	if err := transaction.QueryRow(
		ctx,
		loadCurrentNetworkRevisionSQL,
		claim.WorkspaceID(),
		claim.NetworkID(),
	).Scan(&networkPublicID, &currentRevision); err != nil {
		return network.RevisionAdvanced{}, errors.Join(ErrLoadOutboxRevision, fmt.Errorf("query revision: %w", err))
	}
	if currentRevision < claim.RecordedRevision() {
		return network.RevisionAdvanced{}, errors.Join(ErrLoadOutboxRevision, ErrOutboxRevisionRegressed)
	}
	revision, err = network.NewRevisionAdvanced(networkPublicID, currentRevision)
	if err != nil {
		return network.RevisionAdvanced{}, errors.Join(ErrLoadOutboxRevision, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return network.RevisionAdvanced{}, errors.Join(ErrLoadOutboxRevision, fmt.Errorf("commit revision read: %w", err))
	}
	committed = true
	return revision, nil
}

// MarkRevisionDelivered atomically completes a live claim and appends its
// immutable successful-attempt evidence.
func (store *OutboxStore) MarkRevisionDelivered(
	ctx context.Context,
	claim network.RevisionClaim,
) error {
	if ctx == nil || store == nil || store.database == nil || !claim.IsValid() {
		return ErrInvalidOutboxStore
	}
	return store.finishClaim(
		ctx,
		postgresOperationOutboxMarkDelivered,
		markRevisionDeliveredSQL,
		claim,
	)
}

// RetryNetworkRevision atomically records a typed failed attempt and releases
// its live claim for a bounded future retry.
func (store *OutboxStore) RetryNetworkRevision(
	ctx context.Context,
	claim network.RevisionClaim,
	errorClass string,
	retryDelay time.Duration,
) error {
	if ctx == nil || store == nil || store.database == nil || !claim.IsValid() ||
		!validOutboxErrorClass(errorClass) || retryDelay < time.Millisecond ||
		retryDelay > maxOutboxRetryDelay {
		return ErrInvalidOutboxStore
	}
	return store.finishClaim(
		ctx,
		postgresOperationOutboxRetry,
		retryNetworkRevisionSQL,
		claim,
		retryDelay.Milliseconds(),
		errorClass,
	)
}

func (store *OutboxStore) finishClaim(
	ctx context.Context,
	operation postgresOperation,
	query string,
	claim network.RevisionClaim,
	extraArguments ...any,
) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.metrics.observeOperation(operation, time.Since(startedAt), resultErr)
	}()
	arguments := []any{
		claim.EventID(),
		claim.Token(),
		claim.WorkerID(),
		claim.ClaimedAt(),
	}
	arguments = append(arguments, extraArguments...)
	result, err := store.database.Exec(ctx, query, arguments...)
	if err != nil {
		return errors.Join(ErrFinishOutbox, err)
	}
	if result == nil || result.RowsAffected() != 1 {
		return errors.Join(ErrFinishOutbox, ErrOutboxClaimLost)
	}
	return nil
}

func rollbackOutboxTransaction(transaction outboxTransaction) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), outboxRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back outbox transaction: %w", err)
	}
	return nil
}

func randomClaimToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}

func validOutboxWorkerID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && strings.ContainsRune("._:-", rune(character))) {
			continue
		}
		return false
	}
	return true
}

func validOutboxErrorClass(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
