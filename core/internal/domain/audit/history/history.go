// Package history reads a Workspace's audit history. PostgreSQL
// decides who may read which streams; this package validates queries,
// applies the default window, and rechecks every sealed record it returns,
// so a tampered row is reported rather than shown as sealed.
package history

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalid reports a malformed query or durable result.
	ErrInvalid = errors.New("audit history: invalid query or result")
	// ErrForbidden conceals missing authority or an unavailable scope.
	ErrForbidden = errors.New("audit history: permission denied")
	// ErrUnavailable reports an unavailable dependency.
	ErrUnavailable = errors.New("audit history: unavailable")
)

// Bounds shared with PostgreSQL.
const (
	MaximumPageSize    = 100
	DefaultPageSize    = 50
	MaximumTargetKinds = 16
	// DefaultWindow is what the Console shows unless asked for older events.
	DefaultWindow = 90 * 24 * time.Hour
	// MaximumWindow bounds one query or export to about three months (a
	// calendar quarter plus a day for time zones); older evidence is read
	// window by window.
	MaximumWindow = 93 * 24 * time.Hour
)

const cursorPrefix = "a1."

// Cursor continues a page after its last record: (event time, event id),
// newest first.
type Cursor struct {
	OccurredAt time.Time
	EventID    publicid.ID
}

// Token returns the opaque page token for the cursor.
func (cursor Cursor) Token() string {
	text := strconv.FormatInt(cursor.OccurredAt.UnixMicro(), 10) + "." + cursor.EventID.String()
	return cursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(text))
}

// ParseCursor reads a page token produced by Token.
func ParseCursor(token string) (Cursor, error) {
	encoded, found := strings.CutPrefix(token, cursorPrefix)
	if !found || len(encoded) > 128 {
		return Cursor{}, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Cursor{}, ErrInvalid
	}
	micros, id, found := strings.Cut(string(raw), ".")
	if !found {
		return Cursor{}, ErrInvalid
	}
	value, err := strconv.ParseInt(micros, 10, 64)
	if err != nil || value <= 0 || strconv.FormatInt(value, 10) != micros {
		return Cursor{}, ErrInvalid
	}
	eventID, err := publicid.Parse(id)
	if err != nil || eventID.String() != id {
		return Cursor{}, ErrInvalid
	}
	return Cursor{OccurredAt: time.UnixMicro(value).UTC(), EventID: eventID}, nil
}

// Query selects one page of a Workspace's history. Zero values mean no
// filter; a zero Until is the read's time on the database clock and a zero
// Since is Until minus DefaultWindow (WithDefaultWindow).
type Query struct {
	WorkspaceID   workspace.ID
	NetworkID     network.ID
	Since         time.Time
	Until         time.Time
	TargetKinds   []string
	TargetID      publicid.ID
	ActorID       publicid.ID
	ActorKind     string
	Action        string
	Result        string
	CorrelationID publicid.ID
	ChangeID      publicid.ID
	Cursor        *Cursor
	PageSize      int
}

// IsValid reports a complete query with every default applied.
func (query Query) IsValid() bool {
	return validWindow(query.Since, query.Until) && query.validFilter()
}

// IsValidRequest reports a query that is complete once WithDefaultWindow
// fills a zero Since or Until from the database clock.
func (query Query) IsValidRequest() bool {
	return validRequestWindow(query.Since, query.Until) && query.validFilter()
}

// WithDefaultWindow fills a zero Until with now, the read's time on the
// database clock, and a zero Since with Until minus DefaultWindow.
func (query Query) WithDefaultWindow(now time.Time) Query {
	query.Since, query.Until = defaultWindow(query.Since, query.Until, now)
	return query
}

func defaultWindow(since, until, now time.Time) (time.Time, time.Time) {
	if until.IsZero() {
		until = now
	}
	if since.IsZero() {
		since = until.Add(-DefaultWindow)
	}
	return since.UTC(), until.UTC()
}

func validWindow(since, until time.Time) bool {
	return !since.IsZero() && !until.IsZero() && since.Before(until) && until.Sub(since) <= MaximumWindow
}

// validRequestWindow checks what can be checked before the database clock
// fills the window: a full window, or none, or one end.
func validRequestWindow(since, until time.Time) bool {
	return since.IsZero() || until.IsZero() || validWindow(since, until)
}

func (query Query) validFilter() bool {
	if !query.WorkspaceID.IsValid() || query.PageSize < 1 || query.PageSize > MaximumPageSize ||
		len(query.TargetKinds) > MaximumTargetKinds {
		return false
	}
	optionalIDs := []publicid.ID{publicid.ID(query.NetworkID), query.TargetID, query.ActorID,
		query.CorrelationID, query.ChangeID}
	for _, id := range optionalIDs {
		if id != (publicid.ID{}) && !id.IsValid() {
			return false
		}
	}
	for _, kind := range query.TargetKinds {
		if !validKind(kind) {
			return false
		}
	}
	switch query.ActorKind {
	case "", audit.ActorPrincipal:
	case audit.ActorSystem:
		if query.ActorID != (publicid.ID{}) {
			return false
		}
	default:
		return false
	}
	switch query.Result {
	case "", audit.ResultSucceeded, audit.ResultDenied, audit.ResultFailed:
	default:
		return false
	}
	if query.Action != "" && !validAction(query.Action) {
		return false
	}
	return query.Cursor == nil || (!query.Cursor.OccurredAt.IsZero() && query.Cursor.EventID.IsValid())
}

// Page is one page of records, newest first. Actors names the principals
// in the page who are or were members of the Workspace. Since and Until are
// the window read, with its defaults filled; ReadAt is the read's time on the
// database clock.
type Page struct {
	Records []audit.Record
	Actors  map[string]string
	Next    *Cursor
	Since   time.Time
	Until   time.Time
	ReadAt  time.Time
}

// Store reads one authorized page on the database clock, filling the
// query's default window from it.
type Store interface {
	List(context.Context, accountsession.Session, Query) (Page, error)
}

// Clock supplies this host's time, used only to refuse early a session that
// has already ended; the store authorizes on the database clock.
type Clock interface {
	Now() time.Time
}

// validReadWindow checks the window a store read against the one asked for.
func validReadWindow(page Page, since, until time.Time) bool {
	return validWindow(page.Since, page.Until) && !page.ReadAt.IsZero() &&
		(since.IsZero() || page.Since.Equal(since)) && (until.IsZero() || page.Until.Equal(until))
}

// Service validates queries and rechecks returned seals.
type Service struct {
	store Store
	clock Clock
}

// NewService requires a store and clock.
func NewService(store Store, clock Clock) (*Service, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock}, nil
}

// List applies defaults, reads one page and marks any sealed record whose
// seal does not recompute as seal_mismatch.
func (service *Service) List(ctx context.Context, session accountsession.Session, query Query) (Page, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil {
		return Page{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return Page{}, ErrForbidden
	}
	if query.PageSize == 0 {
		query.PageSize = DefaultPageSize
	}
	query.Since, query.Until = query.Since.UTC(), query.Until.UTC()
	query.TargetKinds = append([]string(nil), query.TargetKinds...)
	if !query.IsValidRequest() {
		return Page{}, ErrInvalid
	}
	page, err := service.store.List(ctx, session, query)
	if err != nil {
		return Page{}, err
	}
	if len(page.Records) > query.PageSize || !validReadWindow(page, query.Since, query.Until) {
		return Page{}, ErrInvalid
	}
	records := make([]audit.Record, len(page.Records))
	for index, record := range page.Records {
		if record.Integrity.Status == audit.IntegritySealed && record.VerifySeal() != nil {
			record.Integrity.Status = audit.IntegritySealMismatch
		}
		records[index] = record
	}
	page.Records = records
	return page, nil
}

func validKind(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character < 'a' || character > 'z' {
			if (character < '0' || character > '9') && character != '_' {
				return false
			}
		}
	}
	return true
}

func validAction(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character < 'a' || character > 'z' {
			if (character < '0' || character > '9') && character != '_' && character != '.' {
				return false
			}
		}
	}
	return true
}

// Export bounds. A larger range must be split; an export never truncates
// silently, because a verifier must see whole runs of each stream.
const (
	ExportChunkSize      = 500
	MaximumExportRecords = 10000
	// MaximumExportBytes approximates the encoded size an export may reach.
	MaximumExportBytes = 14 << 20
)

// ErrExportTooLarge reports a range with more evidence than one export holds.
var ErrExportTooLarge = errors.New("audit history: export too large")

// ExportQuery selects whole streams of a Workspace, or of one Network, in a
// time window. A zero Until is the first chunk's time on the database clock
// and a zero Since is Until minus DefaultWindow.
type ExportQuery struct {
	WorkspaceID workspace.ID
	NetworkID   network.ID
	Since       time.Time
	Until       time.Time
}

// IsValid reports a complete export query with defaults applied.
func (query ExportQuery) IsValid() bool {
	return validWindow(query.Since, query.Until) && query.validScope()
}

// IsValidRequest reports an export query that is complete once
// WithDefaultWindow fills a zero Since or Until from the database clock.
func (query ExportQuery) IsValidRequest() bool {
	return validRequestWindow(query.Since, query.Until) && query.validScope()
}

// WithDefaultWindow fills a zero Until with now, the read's time on the
// database clock, and a zero Since with Until minus DefaultWindow.
func (query ExportQuery) WithDefaultWindow(now time.Time) ExportQuery {
	query.Since, query.Until = defaultWindow(query.Since, query.Until, now)
	return query
}

func (query ExportQuery) validScope() bool {
	return query.WorkspaceID.IsValid() && (query.NetworkID == (network.ID{}) || query.NetworkID.IsValid())
}

// Export is every record in the window, oldest first, as stored. Seals are
// left for the reader to verify; Export does not mark mismatches.
// GeneratedAt is the first chunk's time on the database clock.
type Export struct {
	Query       ExportQuery
	Records     []audit.Record
	Actors      map[string]string
	GeneratedAt time.Time
}

// ExportStore reads one authorized chunk oldest first on the database clock,
// filling the query's default window from it.
type ExportStore interface {
	ExportChunk(ctx context.Context, session accountsession.Session, query ExportQuery,
		after *Cursor, limit int) (Page, error)
}

// Exporter assembles bounded exports.
type Exporter struct {
	store ExportStore
	clock Clock
}

// NewExporter requires a store and clock.
func NewExporter(store ExportStore, clock Clock) (*Exporter, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Exporter{store: store, clock: clock}, nil
}

// Export reads the whole window chunk by chunk, or fails with
// ErrExportTooLarge when it exceeds the record or size bound.
func (exporter *Exporter) Export(ctx context.Context, session accountsession.Session, query ExportQuery) (Export, error) {
	if ctx == nil || exporter == nil || exporter.store == nil || exporter.clock == nil {
		return Export{}, ErrInvalid
	}
	now := exporter.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return Export{}, ErrForbidden
	}
	query.Since, query.Until = query.Since.UTC(), query.Until.UTC()
	if !query.IsValidRequest() {
		return Export{}, ErrInvalid
	}
	result := Export{Records: []audit.Record{}, Actors: map[string]string{}}
	var after *Cursor
	size := 0
	for {
		page, err := exporter.store.ExportChunk(ctx, session, query, after, ExportChunkSize)
		if err != nil {
			return Export{}, err
		}
		if len(page.Records) > ExportChunkSize || !validReadWindow(page, query.Since, query.Until) {
			return Export{}, ErrInvalid
		}
		if result.GeneratedAt.IsZero() {
			// The first chunk fixes the window on the database clock; every
			// later chunk reads exactly that window.
			query.Since, query.Until = page.Since, page.Until
			result.Query, result.GeneratedAt = query, page.ReadAt
		}
		for _, record := range page.Records {
			size += 2*len(record.PayloadCanonical) + 1024
		}
		result.Records = append(result.Records, page.Records...)
		for id, name := range page.Actors {
			result.Actors[id] = name
		}
		if len(result.Records) > MaximumExportRecords || size > MaximumExportBytes {
			return Export{}, ErrExportTooLarge
		}
		if page.Next == nil {
			return result, nil
		}
		after = page.Next
	}
}
