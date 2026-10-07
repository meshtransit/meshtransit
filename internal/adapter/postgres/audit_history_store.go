package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/audit/history"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

// maximumAuditHistoryPageBytes bounds one page: 100 records whose payload
// and payload text are each at most 16 KiB, plus record fields and names.
const maximumAuditHistoryPageBytes = 8 << 20

const listWorkspaceAuditEventsSQL = `SELECT mesh_ops.list_workspace_audit_events_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ,$13::TIMESTAMPTZ,$14::TEXT[],$15::UUID,$16::UUID,NULLIF($17::TEXT,''),
 NULLIF($18::TEXT,''),NULLIF($19::TEXT,''),$20::UUID,$21::UUID,$22::TIMESTAMPTZ,$23::UUID,$24::INTEGER)::TEXT`

// AuditHistoryStore reads Workspace audit history through the runtime pool,
// one short read-only transaction per page.
type AuditHistoryStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ history.Store = (*AuditHistoryStore)(nil)

// NewAuditHistoryStore uses the runtime pool.
func NewAuditHistoryStore(pool *Pool, options AccountSessionOptions) (*AuditHistoryStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, history.ErrInvalid
	}
	return &AuditHistoryStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// List authorizes audit.read in PostgreSQL and returns one page. A Network
// filter binds that exact Network scope first, so Network-bound roles can
// read their own Network.
func (store *AuditHistoryStore) List(ctx context.Context, session accountsession.Session,
	query history.Query) (_ history.Page, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !query.IsValid() {
		return history.Page{}, history.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return history.Page{}, errors.Join(history.ErrUnavailable, err)
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return history.Page{}, errors.Join(history.ErrUnavailable, err)
	}
	if query.NetworkID.IsValid() {
		var workspaceInternal, networkInternal int64
		if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, query.WorkspaceID.String(),
			query.NetworkID.String()).Scan(&workspaceInternal, &networkInternal); err != nil {
			return history.Page{}, auditHistoryError(err)
		}
		if workspaceInternal <= 0 || networkInternal <= 0 {
			return history.Page{}, history.ErrForbidden
		}
	}
	var encoded *string
	if err := tx.QueryRow(ctx, listWorkspaceAuditEventsSQL, auditHistoryArguments(session, query)...).Scan(&encoded); err != nil {
		return history.Page{}, auditHistoryError(err)
	}
	if encoded == nil {
		return history.Page{}, history.ErrForbidden
	}
	return decodeAuditHistoryPage([]byte(*encoded), query.PageSize)
}

func auditHistoryArguments(session accountsession.Session, query history.Query) []any {
	var kinds []string
	if len(query.TargetKinds) > 0 {
		kinds = append([]string(nil), query.TargetKinds...)
	}
	var cursorAt *time.Time
	var cursorID *string
	if query.Cursor != nil {
		at, id := query.Cursor.OccurredAt, query.Cursor.EventID.String()
		cursorAt, cursorID = &at, &id
	}
	return append(sessionQueryArguments(session), query.WorkspaceID.String(),
		optionalUUIDText(publicid.ID(query.NetworkID)), query.Since, query.Until, kinds,
		optionalUUIDText(query.TargetID), optionalUUIDText(query.ActorID), query.ActorKind, query.Action,
		query.Result, optionalUUIDText(query.CorrelationID), optionalUUIDText(query.ChangeID),
		cursorAt, cursorID, query.PageSize)
}

func optionalUUIDText(id publicid.ID) *string {
	if id == (publicid.ID{}) {
		return nil
	}
	text := id.String()
	return &text
}

type auditHistoryPageRecord struct {
	Records []audit.Record    `json:"records"`
	HasMore *bool             `json:"has_more"`
	Actors  map[string]string `json:"actors"`
}

func decodeAuditHistoryPage(encoded []byte, pageSize int) (history.Page, error) {
	if len(encoded) == 0 || len(encoded) > maximumAuditHistoryPageBytes {
		return history.Page{}, history.ErrInvalid
	}
	var record auditHistoryPageRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&record); err != nil || record.HasMore == nil || record.Records == nil ||
		record.Actors == nil || len(record.Records) > pageSize || (*record.HasMore && len(record.Records) != pageSize) {
		return history.Page{}, history.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return history.Page{}, history.ErrInvalid
	}
	for _, item := range record.Records {
		if !validAuditHistoryRecord(item) {
			return history.Page{}, history.ErrInvalid
		}
	}
	for id, name := range record.Actors {
		if parsed, err := publicid.Parse(id); err != nil || parsed.String() != id || name == "" || len(name) > 256 {
			return history.Page{}, history.ErrInvalid
		}
	}
	page := history.Page{Records: record.Records, Actors: record.Actors}
	if *record.HasMore {
		last := record.Records[len(record.Records)-1]
		occurred, err := time.Parse(audit.RecordTimeLayout, last.EventTime)
		eventID, idErr := publicid.Parse(last.EventID)
		if err != nil || idErr != nil {
			return history.Page{}, history.ErrInvalid
		}
		page.Next = &history.Cursor{OccurredAt: occurred, EventID: eventID}
	}
	return page, nil
}

// validAuditHistoryRecord checks the record shape. A sealed record must
// parse into seal material; the service recomputes the seal itself.
func validAuditHistoryRecord(record audit.Record) bool {
	switch record.Integrity.Status {
	case audit.IntegritySealed:
		_, err := record.SealMaterial()
		return err == nil
	case audit.IntegrityLegacyUnsealed:
		_, timeErr := time.Parse(audit.RecordTimeLayout, record.EventTime)
		_, idErr := publicid.Parse(record.EventID)
		return record.RecordVersion == audit.RecordVersion && timeErr == nil && idErr == nil &&
			record.Integrity == audit.RecordIntegrity{Status: audit.IntegrityLegacyUnsealed}
	default:
		return false
	}
}

// auditHistoryError conceals missing authority and separates invalid input.
func auditHistoryError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return history.ErrForbidden
		case "22023", "22P02":
			return history.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return history.ErrForbidden
	}
	return errors.Join(history.ErrUnavailable, err)
}
