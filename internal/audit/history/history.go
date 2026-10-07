// Package history reads a Workspace's audit history (R1-64). PostgreSQL
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

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
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
// filter; a zero Since/Until takes the default window ending now.
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
	if !query.WorkspaceID.IsValid() || query.Since.IsZero() || query.Until.IsZero() ||
		!query.Since.Before(query.Until) || query.PageSize < 1 || query.PageSize > MaximumPageSize ||
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
// in the page who are or were members of the Workspace.
type Page struct {
	Records []audit.Record
	Actors  map[string]string
	Next    *Cursor
	Since   time.Time
	Until   time.Time
}

// Store reads one authorized page.
type Store interface {
	List(context.Context, accountsession.Session, Query) (Page, error)
}

// Clock supplies the current time.
type Clock interface {
	Now() time.Time
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
	if query.Until.IsZero() {
		query.Until = now
	}
	if query.Since.IsZero() {
		query.Since = query.Until.Add(-DefaultWindow)
	}
	if query.PageSize == 0 {
		query.PageSize = DefaultPageSize
	}
	query.Since, query.Until = query.Since.UTC(), query.Until.UTC()
	query.TargetKinds = append([]string(nil), query.TargetKinds...)
	if !query.IsValid() {
		return Page{}, ErrInvalid
	}
	page, err := service.store.List(ctx, session, query)
	if err != nil {
		return Page{}, err
	}
	if len(page.Records) > query.PageSize {
		return Page{}, ErrInvalid
	}
	records := make([]audit.Record, len(page.Records))
	for index, record := range page.Records {
		if record.Integrity.Status == audit.IntegritySealed && record.VerifySeal() != nil {
			record.Integrity.Status = audit.IntegritySealMismatch
		}
		records[index] = record
	}
	page.Records, page.Since, page.Until = records, query.Since, query.Until
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
