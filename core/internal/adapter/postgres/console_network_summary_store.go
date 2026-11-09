package postgres

import (
	"context"
	"errors"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/networksummary"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	readConsoleNetworkSummariesSQL = `SELECT mesh_ops.read_console_network_summaries_v1(` + sessionArguments + `,
 $10::UUID,$11::TIMESTAMPTZ,$12::UUID,$13::INTEGER,$14::TEXT)::TEXT`
	readConsoleWorkspaceOverviewSQL = `SELECT mesh_ops.read_console_workspace_overview_v1(` + sessionArguments + `,
 $10::UUID,$11::TIMESTAMPTZ)::TEXT`
	readConsoleNetworkSummarySQL = `SELECT mesh_ops.read_console_network_summary_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ)::TEXT`
	maximumConsoleSummaryBytes = 2 << 20
)

// ConsoleNetworkSummaryStore reads Network summaries for the Console
// through the runtime pool, each read in one transaction on its own clock.
type ConsoleNetworkSummaryStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ networksummary.Reader = (*ConsoleNetworkSummaryStore)(nil)

// NewConsoleNetworkSummaryStore rejects non-runtime pools before any effect.
func NewConsoleNetworkSummaryStore(pool *Pool, options AccountSessionOptions) (*ConsoleNetworkSummaryStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, networksummary.ErrInvalidRead
	}
	return &ConsoleNetworkSummaryStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func consoleSummaryError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		// 23503: an unknown or mismatched Workspace and Network, answered as
		// a refusal so that existence is not told apart.
		case "42501", "23503":
			return networksummary.ErrReadForbidden
		case "22023":
			return networksummary.ErrInvalidRead
		// Go checks every identifier first: a cast failure is server data.
		case "22P02":
			return networksummary.ErrInvalidResult
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return networksummary.ErrReadForbidden
	}
	return errors.Join(networksummary.ErrReadUnavailable, err)
}

// read runs one statement in a fresh transaction: timeouts, optional exact
// Network scope, the transaction's own time, then the statement.
func (store *ConsoleNetworkSummaryStore) read(ctx context.Context, scope *network.Scope,
	query func(evaluatedAt time.Time) (string, []any)) (_ *string, resultErr error) {
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(networksummary.ErrReadUnavailable, err)
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return nil, errors.Join(networksummary.ErrReadUnavailable, err)
	}
	if scope != nil {
		var workspaceInternal, networkInternal int64
		if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
			scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
			return nil, consoleSummaryError(err)
		}
		if workspaceInternal <= 0 || networkInternal <= 0 {
			return nil, networksummary.ErrReadForbidden
		}
	}
	evaluatedAt, err := readTransactionTime(ctx, tx.QueryRow)
	if err != nil {
		return nil, errors.Join(networksummary.ErrReadUnavailable, err)
	}
	statement, args := query(evaluatedAt)
	var encoded *string
	if err := tx.QueryRow(ctx, statement, args...).Scan(&encoded); err != nil {
		return nil, consoleSummaryError(err)
	}
	return encoded, nil
}

func (store *ConsoleNetworkSummaryStore) usable(ctx context.Context, session accountsession.Session) bool {
	return ctx != nil && store != nil && store.database != nil && validAccountSessionOptions(store.options) &&
		session.IsValid()
}

// ReadPage reads one page of the Networks the Session may read.
func (store *ConsoleNetworkSummaryStore) ReadPage(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID, request networksummary.PageRequest) (networksummary.Page, error) {
	if !store.usable(ctx, session) || !workspaceID.IsValid() || !networksummary.ValidPageRequest(request) {
		return networksummary.Page{}, networksummary.ErrInvalidRead
	}
	encoded, err := store.read(ctx, nil, func(evaluatedAt time.Time) (string, []any) {
		var after, query any
		if request.After.IsValid() {
			after = request.After.String()
		}
		if request.Query != "" {
			query = request.Query
		}
		return readConsoleNetworkSummariesSQL, append(sessionQueryArguments(session), workspaceID.String(),
			evaluatedAt, after, request.Limit, query)
	})
	if err != nil {
		return networksummary.Page{}, err
	}
	if encoded == nil {
		return networksummary.Page{}, networksummary.ErrReadForbidden
	}
	var record struct {
		Items       []consoleSummaryItemRecord `json:"items"`
		NextAfter   *string                    `json:"next_after"`
		SearchedAll bool                       `json:"searched_all"`
	}
	if err := decodeStrictJSON(*encoded, maximumConsoleSummaryBytes, &record); err != nil ||
		record.Items == nil || len(record.Items) > request.Limit {
		return networksummary.Page{}, networksummary.ErrInvalidResult
	}
	page := networksummary.Page{Items: make([]networksummary.Figures, 0, len(record.Items)),
		SearchedAll: record.SearchedAll}
	for _, item := range record.Items {
		figures, err := item.figures()
		if err != nil {
			return networksummary.Page{}, err
		}
		page.Items = append(page.Items, figures)
	}
	if record.NextAfter != nil {
		next, err := network.ParseID(*record.NextAfter)
		if err != nil {
			return networksummary.Page{}, networksummary.ErrInvalidResult
		}
		page.Next = next
	}
	return page, nil
}

// ReadNetwork reads one Network's summary under its exact scope.
func (store *ConsoleNetworkSummaryStore) ReadNetwork(ctx context.Context, session accountsession.Session,
	scope network.Scope) (networksummary.Figures, error) {
	if !store.usable(ctx, session) || !scope.IsValid() {
		return networksummary.Figures{}, networksummary.ErrInvalidRead
	}
	// The projection finds the Network in the Workspace itself.
	encoded, err := store.read(ctx, nil, func(evaluatedAt time.Time) (string, []any) {
		return readConsoleNetworkSummarySQL, append(sessionQueryArguments(session), scope.WorkspaceID().String(),
			scope.NetworkID().String(), evaluatedAt)
	})
	if err != nil {
		return networksummary.Figures{}, err
	}
	if encoded == nil {
		return networksummary.Figures{}, networksummary.ErrReadForbidden
	}
	var record consoleSummaryItemRecord
	if err := decodeStrictJSON(*encoded, maximumConsoleSummaryBytes, &record); err != nil {
		return networksummary.Figures{}, networksummary.ErrInvalidResult
	}
	figures, err := record.figures()
	if err != nil || figures.NetworkID != scope.NetworkID() {
		return networksummary.Figures{}, networksummary.ErrInvalidResult
	}
	return figures, nil
}

type consoleSummarySideRecord struct {
	Kind        string  `json:"kind"`
	ID          *string `json:"id"`
	DisplayCode *string `json:"display_code"`
}

// ReadOverview reads the Workspace totals and links.
func (store *ConsoleNetworkSummaryStore) ReadOverview(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (networksummary.Overview, error) {
	if !store.usable(ctx, session) || !workspaceID.IsValid() {
		return networksummary.Overview{}, networksummary.ErrInvalidRead
	}
	encoded, err := store.read(ctx, nil, func(evaluatedAt time.Time) (string, []any) {
		return readConsoleWorkspaceOverviewSQL, append(sessionQueryArguments(session), workspaceID.String(),
			evaluatedAt)
	})
	if err != nil {
		return networksummary.Overview{}, err
	}
	if encoded == nil {
		return networksummary.Overview{}, networksummary.ErrReadForbidden
	}
	var record struct {
		Networks             int64      `json:"networks"`
		AddressesTaken       int64      `json:"addresses_taken"`
		ActiveContracts      int64      `json:"active_contracts"`
		CrossWorkspace       int64      `json:"cross_workspace_contracts"`
		OffersWaiting        int64      `json:"offers_waiting"`
		AddressesPartial     bool       `json:"addresses_partial"`
		SharesPartial        bool       `json:"shares_partial"`
		OldestComputedAt     *time.Time `json:"oldest_computed_at"`
		LinksPartial         bool       `json:"links_partial"`
		WorkspaceDisplayCode *string    `json:"workspace_display_code"`
		Links                []struct {
			From    consoleSummarySideRecord `json:"from"`
			To      consoleSummarySideRecord `json:"to"`
			Active  int64                    `json:"active"`
			Waiting int64                    `json:"waiting"`
		} `json:"links"`
	}
	if err := decodeStrictJSON(*encoded, maximumConsoleSummaryBytes, &record); err != nil ||
		record.Links == nil || len(record.Links) > networksummary.MaximumLinks || record.Networks < 0 ||
		record.AddressesTaken < 0 || record.ActiveContracts < 0 || record.CrossWorkspace < 0 ||
		record.OffersWaiting < 0 || record.CrossWorkspace > record.ActiveContracts {
		return networksummary.Overview{}, networksummary.ErrInvalidResult
	}
	overview := networksummary.Overview{Networks: record.Networks, AddressesTaken: record.AddressesTaken,
		ActiveContracts: record.ActiveContracts, CrossWorkspace: record.CrossWorkspace,
		OffersWaiting: record.OffersWaiting, AddressesPartial: record.AddressesPartial,
		SharesPartial: record.SharesPartial, LinksPartial: record.LinksPartial,
		Links: make([]networksummary.Link, 0, len(record.Links))}
	if record.WorkspaceDisplayCode != nil {
		overview.WorkspaceDisplayCode = *record.WorkspaceDisplayCode
	}
	if record.OldestComputedAt != nil {
		at := record.OldestComputedAt.UTC()
		overview.OldestComputedAt = &at
	}
	for _, link := range record.Links {
		from, fromErr := link.From.side()
		to, toErr := link.To.side()
		if fromErr != nil || toErr != nil || link.Active < 0 || link.Waiting < 0 || link.Active+link.Waiting == 0 {
			return networksummary.Overview{}, networksummary.ErrInvalidResult
		}
		overview.Links = append(overview.Links, networksummary.Link{From: from, To: to, Active: link.Active,
			Waiting: link.Waiting})
	}
	return overview, nil
}

func (record consoleSummarySideRecord) side() (networksummary.Side, error) {
	switch {
	case record.Kind == "network" && record.ID != nil && record.DisplayCode == nil:
		id, err := network.ParseID(*record.ID)
		if err != nil {
			return networksummary.Side{}, networksummary.ErrInvalidResult
		}
		return networksummary.Side{NetworkID: id}, nil
	case record.Kind == "workspace" && record.ID == nil && record.DisplayCode != nil && validDisplayCode(*record.DisplayCode):
		return networksummary.Side{DisplayCode: *record.DisplayCode}, nil
	default:
		return networksummary.Side{}, networksummary.ErrInvalidResult
	}
}

func validDisplayCode(code string) bool {
	if len(code) != 12 {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

type consoleSummaryItemRecord struct {
	NetworkID          string     `json:"network_id"`
	DisplayName        string     `json:"display_name"`
	DisplayCode        *string    `json:"display_code"`
	Permissions        []string   `json:"permissions"`
	ComputedAt         *time.Time `json:"computed_at"`
	IPv4Prefix         *string    `json:"ipv4_prefix"`
	AddressesCapacity  *int64     `json:"addresses_capacity"`
	AddressesInUse     *int64     `json:"addresses_in_use"`
	AddressesHeld      *int64     `json:"addresses_held"`
	KubernetesClusters *int64     `json:"kubernetes_clusters"`
	ActiveDevices      *int64     `json:"active_devices"`
	RuleCount          *int64     `json:"rule_count"`
	PolicyRevision     *int64     `json:"policy_revision"`
	PolicyPublishedAt  *time.Time `json:"policy_published_at"`
	PendingApprovals   *int64     `json:"pending_approvals"`
	SharesOutActive    *int64     `json:"shares_out_active"`
	SharesInActive     *int64     `json:"shares_in_active"`
	OffersWaiting      *int64     `json:"offers_waiting"`
	Sites              *int64     `json:"sites"`
}

func (record consoleSummaryItemRecord) figures() (networksummary.Figures, error) {
	id, err := network.ParseID(record.NetworkID)
	if err != nil || record.DisplayName == "" || utf8.RuneCountInString(record.DisplayName) > 128 ||
		len(record.Permissions) > 16 {
		return networksummary.Figures{}, networksummary.ErrInvalidResult
	}
	figures := networksummary.Figures{NetworkID: id, DisplayName: record.DisplayName,
		Permissions: append([]string(nil), record.Permissions...), ComputedAt: record.ComputedAt,
		AddressesCapacity: record.AddressesCapacity, AddressesInUse: record.AddressesInUse,
		AddressesHeld: record.AddressesHeld, KubernetesClusters: record.KubernetesClusters,
		ActiveDevices: record.ActiveDevices, RuleCount: record.RuleCount, PolicyRevision: record.PolicyRevision,
		PolicyPublishedAt: record.PolicyPublishedAt, PendingApprovals: record.PendingApprovals,
		SharesOutActive: record.SharesOutActive, SharesInActive: record.SharesInActive,
		OffersWaiting: record.OffersWaiting, Sites: record.Sites}
	if record.DisplayCode != nil {
		if !validDisplayCode(*record.DisplayCode) {
			return networksummary.Figures{}, networksummary.ErrInvalidResult
		}
		figures.DisplayCode = *record.DisplayCode
	}
	if record.IPv4Prefix != nil {
		prefix, err := netip.ParsePrefix(*record.IPv4Prefix)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return networksummary.Figures{}, networksummary.ErrInvalidResult
		}
		figures.IPv4Prefix = &prefix
	}
	for _, count := range []*int64{record.AddressesCapacity, record.AddressesInUse, record.AddressesHeld,
		record.KubernetesClusters, record.ActiveDevices, record.RuleCount, record.PendingApprovals,
		record.SharesOutActive, record.SharesInActive, record.OffersWaiting, record.Sites} {
		if count != nil && *count < 0 {
			return networksummary.Figures{}, networksummary.ErrInvalidResult
		}
	}
	return figures, nil
}
