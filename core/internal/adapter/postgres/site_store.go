package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
)

const maximumSiteDocumentBytes = 8 << 20

const listSitesSQL = `SELECT mesh_ops.list_sites_v1(` + sessionArguments + `,$10::UUID,$11::UUID,
 NULLIF($12::TEXT,'')::UUID,$13::INTEGER)::TEXT`

const readPolicySitesSQL = `SELECT mesh_ops.read_policy_sites_v1(` + sessionArguments + `,$10::UUID,$11::UUID,
 $12::UUID[])::TEXT`

const readSiteSQL = `SELECT mesh_ops.read_site_v2(` + sessionArguments + `,$10::UUID,$11::UUID,$12::UUID)::TEXT`

const listSitePrimaryChangesSQL = `SELECT mesh_ops.list_site_primary_changes_v1(` + sessionArguments +
	`,$10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::INTEGER)::TEXT`

const changeSiteSQL = `SELECT mesh_ops.change_site_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::UUID,$14::BIGINT,$15::TEXT,$16::CIDR[],$17::BOOLEAN,$18::BOOLEAN,
 $19::JSONB,$20::INTEGER,$21::UUID)::TEXT`

const changeSiteRouterSQL = `SELECT mesh_ops.change_site_router_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::UUID,$14::BIGINT,$15::UUID,$16::INTEGER,$17::TEXT,$18::INTEGER,
 $19::UUID,$20::UUID)::TEXT`

const appendSiteEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network_site',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,$12::TEXT,
 $13::UUID,$14::BYTEA,$15::BYTEA,$16::JSONB,'network.revision.advanced',$17::JSONB)`

// SiteStore reads and changes the Sites of a Network through the runtime
// pool. Each change commits with its evidence on the Network stream and wakes
// map sessions through the revision outbox.
type SiteStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ site.Store = (*SiteStore)(nil)

// NewSiteStore uses the runtime pool.
func NewSiteStore(pool *Pool, options AccountSessionOptions) (*SiteStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, site.ErrInvalid
	}
	return &SiteStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func siteDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return site.ErrForbidden
		case "P0002":
			return site.ErrNotFound
		case "40001":
			return site.ErrVersionConflict
		case "MTS01":
			return site.ErrNameTaken
		case "MTS02":
			return site.ErrSiteLimit
		case "MTS03":
			return site.ErrRouterLimit
		case "MTS04":
			return site.ErrRouterNotEligible
		case "MTS05":
			return site.ErrRouterNotOffering
		case "MTS06":
			return site.ErrInUse
		case "MTS08":
			return site.ErrPrefixesInUse
		case "MTS09":
			return site.ErrInvalidPrefix
		case "22023", "22P02", "23514":
			return site.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return site.ErrForbidden
	}
	return errors.Join(site.ErrUnavailable, err)
}

// begin starts one unit of work in the Network scope.
func (store *SiteStore) begin(ctx context.Context, scope network.Scope) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, site.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(site.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(site.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return tx, siteDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return tx, site.ErrForbidden
	}
	return tx, nil
}

func decodeSiteJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumSiteDocumentBytes {
		return site.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return site.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return site.ErrInvalid
	}
	return nil
}

type siteProbeDocument struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
	Port    uint16 `json:"port"`
}

type siteRouterDocument struct {
	DeviceID    string    `json:"device_id"`
	DeviceName  string    `json:"device_name"`
	DeviceState string    `json:"device_state"`
	Ownership   string    `json:"ownership"`
	OffersSite  bool      `json:"offers_site"`
	Priority    int       `json:"priority"`
	State       string    `json:"state"`
	AddedAt     time.Time `json:"added_at"`
}

type siteDocument struct {
	ID         string               `json:"site_id"`
	Name       string               `json:"name"`
	Prefixes   []string             `json:"prefixes"`
	Masquerade bool                 `json:"masquerade"`
	Failback   bool                 `json:"failback"`
	Probes     []siteProbeDocument  `json:"probes"`
	State      string               `json:"state"`
	Version    int64                `json:"version"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	Routers    []siteRouterDocument `json:"routers"`
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, site.ErrInvalid
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func probeKindText(kind site.ProbeKind) string {
	if kind == site.ProbeTCP {
		return "tcp"
	}
	return "icmp"
}

func (document siteDocument) site(allowDeleted bool) (site.Site, error) {
	id, err := site.ParseID(document.ID)
	if err != nil || (document.State != "active" && (!allowDeleted || document.State != "deleted")) ||
		document.Version <= 0 || document.CreatedAt.IsZero() || document.UpdatedAt.Before(document.CreatedAt) {
		return site.Site{}, site.ErrInvalid
	}
	prefixes, err := parsePrefixes(document.Prefixes)
	if err != nil {
		return site.Site{}, err
	}
	probes := make([]site.Probe, 0, len(document.Probes))
	for _, item := range document.Probes {
		address, err := netip.ParseAddr(item.Address)
		kind := map[string]site.ProbeKind{"icmp": site.ProbeICMP, "tcp": site.ProbeTCP}[item.Kind]
		if err != nil || kind == 0 {
			return site.Site{}, site.ErrInvalid
		}
		probes = append(probes, site.Probe{Address: address, Kind: kind, Port: item.Port})
	}
	stored := site.Site{
		ID: id, Version: document.Version, CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
		Definition: site.Definition{
			Name: document.Name, Prefixes: prefixes, Masquerade: document.Masquerade,
			Failback: document.Failback, Probes: probes,
		},
		Routers: make([]site.Router, 0, len(document.Routers)),
	}
	for _, item := range document.Routers {
		router, err := item.router()
		if err != nil {
			return site.Site{}, err
		}
		stored.Routers = append(stored.Routers, router)
	}
	return stored, nil
}

func (document siteRouterDocument) router() (site.Router, error) {
	deviceID, err := node.ParseID(document.DeviceID)
	if err != nil || document.AddedAt.IsZero() {
		return site.Router{}, site.ErrInvalid
	}
	state := map[string]site.RouterState{"active": site.RouterActive, "draining": site.RouterDraining}[document.State]
	router := site.Router{
		RouterAssignment: site.RouterAssignment{DeviceID: deviceID, Priority: document.Priority, State: state},
		DeviceName:       document.DeviceName,
		Eligible:         site.Eligible(document.DeviceState, document.Ownership, document.OffersSite),
		AddedAt:          document.AddedAt,
	}
	if router.Validate() != nil {
		return site.Router{}, site.ErrInvalid
	}
	return router, nil
}

// List authorizes route.read and returns one page of active Sites.
func (store *SiteStore) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	after site.ID, limit int) (_ site.Listing, resultErr error) {
	if !session.IsValid() || !scope.IsValid() || limit < 1 || limit > site.MaximumPage {
		return site.Listing{}, site.ErrInvalid
	}
	afterText := ""
	if after.IsValid() {
		afterText = after.String()
	}
	var envelope struct {
		Sites     []siteDocument `json:"sites"`
		HasMore   bool           `json:"has_more"`
		CanManage bool           `json:"can_manage"`
		CanDelete bool           `json:"can_delete"`
	}
	if err := store.read(ctx, session, scope, listSitesSQL, &envelope, afterText, limit); err != nil {
		return site.Listing{}, err
	}
	if envelope.Sites == nil || len(envelope.Sites) > limit {
		return site.Listing{}, site.ErrInvalid
	}
	listing := site.Listing{Sites: make([]site.Site, 0, len(envelope.Sites)), HasMore: envelope.HasMore,
		Abilities: site.Abilities{CanManage: envelope.CanManage, CanDelete: envelope.CanDelete}}
	for _, document := range envelope.Sites {
		stored, err := document.site(false)
		if err != nil {
			return site.Listing{}, err
		}
		listing.Sites = append(listing.Sites, stored)
	}
	return listing, nil
}

// Read authorizes route.read and returns one active Site.
func (store *SiteStore) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	id site.ID) (site.Reading, error) {
	if !session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return site.Reading{}, site.ErrInvalid
	}
	var envelope struct {
		Site      siteDocument         `json:"site"`
		Primary   *sitePrimaryDocument `json:"primary"`
		CanManage bool                 `json:"can_manage"`
		CanDelete bool                 `json:"can_delete"`
	}
	if err := store.read(ctx, session, scope, readSiteSQL, &envelope, id.String()); err != nil {
		return site.Reading{}, err
	}
	stored, err := envelope.Site.site(false)
	if err != nil || stored.ID != id {
		return site.Reading{}, site.ErrInvalid
	}
	reading := site.Reading{Site: stored, Abilities: site.Abilities{CanManage: envelope.CanManage,
		CanDelete: envelope.CanDelete}}
	if envelope.Primary != nil {
		primary, err := envelope.Primary.primary()
		if err != nil {
			return site.Reading{}, err
		}
		reading.Primary = &primary
	}
	return reading, nil
}

type sitePrimaryDocument struct {
	DeviceID   *string   `json:"device_id"`
	Generation int64     `json:"generation"`
	Reason     string    `json:"reason"`
	ElectedAt  time.Time `json:"elected_at"`
}

func (document sitePrimaryDocument) primary() (site.Primary, error) {
	primary := site.Primary{Generation: document.Generation, Reason: document.Reason, ElectedAt: document.ElectedAt.UTC()}
	if document.DeviceID != nil {
		device, err := node.ParseID(*document.DeviceID)
		if err != nil {
			return site.Primary{}, site.ErrInvalid
		}
		primary.Device = device
	}
	if !primary.IsValid() {
		return site.Primary{}, site.ErrInvalid
	}
	return primary, nil
}

type sitePrimaryChangeDocument struct {
	EventID    string    `json:"event_id"`
	OccurredAt time.Time `json:"occurred_at"`
	DeviceID   *string   `json:"device_id"`
	PreviousID *string   `json:"previous_device_id"`
	Reason     string    `json:"reason"`
	Generation int64     `json:"generation"`
}

// PrimaryChanges reads one page of a Site's primary changes from the audit
// history, newest first.
func (store *SiteStore) PrimaryChanges(ctx context.Context, session accountsession.Session, scope network.Scope,
	id site.ID, after publicid.ID, limit int) (site.PrimaryHistory, error) {
	if !session.IsValid() || !scope.IsValid() || !id.IsValid() || limit < 1 || limit > site.MaximumHistoryPage {
		return site.PrimaryHistory{}, site.ErrInvalid
	}
	var afterText any
	if after != (publicid.ID{}) {
		afterText = after.String()
	}
	var envelope struct {
		Changes []sitePrimaryChangeDocument `json:"changes"`
		HasMore bool                        `json:"has_more"`
	}
	if err := store.read(ctx, session, scope, listSitePrimaryChangesSQL, &envelope, id.String(), afterText,
		limit); err != nil {
		return site.PrimaryHistory{}, err
	}
	if envelope.Changes == nil || len(envelope.Changes) > limit {
		return site.PrimaryHistory{}, site.ErrInvalid
	}
	history := site.PrimaryHistory{HasMore: envelope.HasMore, Changes: make([]site.PrimaryChange, 0, len(envelope.Changes))}
	optionalDevice := func(text *string) (node.ID, bool) {
		if text == nil {
			return node.ID{}, true
		}
		device, err := node.ParseID(*text)
		return device, err == nil
	}
	for _, document := range envelope.Changes {
		eventID, err := publicid.Parse(document.EventID)
		device, deviceOK := optionalDevice(document.DeviceID)
		previous, previousOK := optionalDevice(document.PreviousID)
		change := site.PrimaryChange{EventID: eventID, OccurredAt: document.OccurredAt.UTC(), Device: device,
			Previous: previous, Reason: document.Reason, Generation: document.Generation}
		if err != nil || !deviceOK || !previousOK || !change.IsValid() {
			return site.PrimaryHistory{}, site.ErrInvalid
		}
		history.Changes = append(history.Changes, change)
	}
	return history, nil
}

// ResolvePolicySites authorizes route.read and returns the active Sites of
// the scope among ids, for the policy compiler. Unknown Sites are absent.
func (store *SiteStore) ResolvePolicySites(ctx context.Context, session accountsession.Session,
	scope network.Scope, ids []site.ID) ([]site.Site, error) {
	if !session.IsValid() || !scope.IsValid() || len(ids) == 0 || len(ids) > site.MaximumSitesPerNetwork {
		return nil, site.ErrInvalid
	}
	texts := make([]string, len(ids))
	for index, id := range ids {
		if !id.IsValid() {
			return nil, site.ErrInvalid
		}
		texts[index] = id.String()
	}
	var envelope struct {
		Sites []siteDocument `json:"sites"`
	}
	if err := store.read(ctx, session, scope, readPolicySitesSQL, &envelope, texts); err != nil {
		return nil, err
	}
	if envelope.Sites == nil || len(envelope.Sites) > len(ids) {
		return nil, site.ErrInvalid
	}
	sites := make([]site.Site, 0, len(envelope.Sites))
	for _, document := range envelope.Sites {
		stored, err := document.site(false)
		if err != nil {
			return nil, err
		}
		sites = append(sites, stored)
	}
	return sites, nil
}

// read runs one read function in its own transaction and decodes its result.
func (store *SiteStore) read(ctx context.Context, session accountsession.Session, scope network.Scope,
	statement string, target any, arguments ...any) (resultErr error) {
	tx, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return err
	}
	var encoded string
	if err := tx.QueryRow(ctx, statement, append(append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String()), arguments...)...).Scan(&encoded); err != nil {
		return siteDatabaseError(err)
	}
	return decodeSiteJSON([]byte(encoded), target)
}

type siteChangeRecord struct {
	Site            siteDocument  `json:"site"`
	Previous        *siteDocument `json:"previous"`
	Changed         bool          `json:"changed"`
	NetworkRevision int64         `json:"network_revision"`
	RouteRevision   int64         `json:"route_revision"`
	RoleBindingID   *string       `json:"role_binding_id"`
}

func probesJSON(probes []site.Probe) ([]byte, error) {
	documents := make([]siteProbeDocument, 0, len(probes))
	for _, probe := range probes {
		documents = append(documents, siteProbeDocument{
			Address: probe.Address.String(), Kind: probeKindText(probe.Kind), Port: probe.Port,
		})
	}
	return json.Marshal(documents)
}

func prefixTexts(prefixes []netip.Prefix) []string {
	texts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		texts = append(texts, prefix.String())
	}
	return texts
}

// Change authorizes route.approve (route.withdraw to delete), applies the change and commits it with its
// evidence.
func (store *SiteStore) Change(ctx context.Context, change site.Change) (_ site.Result, resultErr error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.SiteID.IsValid() ||
		!change.CorrelationID.IsValid() {
		return site.Result{}, site.ErrInvalid
	}
	var expected, name, prefixes, masquerade, failback, probes, limit any
	if change.Operation != site.OperationCreate {
		expected = change.ExpectedVersion
	} else {
		limit = change.SiteLimit
	}
	if change.Operation != site.OperationDelete {
		encodedProbes, err := probesJSON(change.Definition.Probes)
		if err != nil {
			return site.Result{}, site.ErrInvalid
		}
		name, prefixes = change.Definition.Name, prefixTexts(change.Definition.Prefixes)
		masquerade, failback, probes = change.Definition.Masquerade, change.Definition.Failback, encodedProbes
	}
	permission := "route.approve"
	if change.Operation == site.OperationDelete {
		permission = "route.withdraw"
	}
	return store.commit(ctx, change.Session, change.Scope, change.CorrelationID, siteAction(change.Operation), permission,
		change.Operation == site.OperationDelete, change.SiteID, change.ExpectedVersion, node.ID{},
		func(tx accountSessionTransaction, changeID publicid.ID) (string, error) {
			var encoded string
			err := tx.QueryRow(ctx, changeSiteSQL, append(sessionQueryArguments(change.Session),
				change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), string(change.Operation),
				change.SiteID.String(), expected, name, prefixes, masquerade, failback, probes, limit,
				changeID.String())...).Scan(&encoded)
			return encoded, err
		})
}

// ChangeRouter authorizes route.approve (route.withdraw to remove) and adds, changes or removes a router.
func (store *SiteStore) ChangeRouter(ctx context.Context, change site.RouterChange) (_ site.Result, resultErr error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.SiteID.IsValid() ||
		!change.Assignment.DeviceID.IsValid() || change.ExpectedVersion <= 0 || !change.CorrelationID.IsValid() {
		return site.Result{}, site.ErrInvalid
	}
	var priority, state, limit, rowID any
	action, permission := "network_site.router_removed", "route.withdraw"
	if change.Operation == site.RouterPut {
		if !change.RouterRowID.IsValid() {
			return site.Result{}, site.ErrInvalid
		}
		priority, limit, rowID = change.Assignment.Priority, change.RouterLimit, change.RouterRowID.String()
		state = map[site.RouterState]string{site.RouterActive: "active", site.RouterDraining: "draining"}[change.Assignment.State]
		action, permission = "network_site.router_set", "route.approve"
	}
	return store.commit(ctx, change.Session, change.Scope, change.CorrelationID, action, permission, false, change.SiteID,
		change.ExpectedVersion, change.Assignment.DeviceID, func(tx accountSessionTransaction, changeID publicid.ID) (string, error) {
			var encoded string
			err := tx.QueryRow(ctx, changeSiteRouterSQL, append(sessionQueryArguments(change.Session),
				change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), string(change.Operation),
				change.SiteID.String(), change.ExpectedVersion, change.Assignment.DeviceID.String(), priority, state,
				limit, rowID, changeID.String())...).Scan(&encoded)
			return encoded, err
		})
}

func siteAction(operation site.Operation) string {
	switch operation {
	case site.OperationCreate:
		return "network_site.created"
	case site.OperationUpdate:
		return "network_site.updated"
	default:
		return "network_site.deleted"
	}
}

// commit runs one change function, checks its record and appends evidence.
func (store *SiteStore) commit(ctx context.Context, session accountsession.Session, scope network.Scope,
	correlationID publicid.ID, action, permission string, deleted bool, siteID site.ID, expectedVersion int64,
	router node.ID, apply func(accountSessionTransaction, publicid.ID) (string, error)) (_ site.Result, resultErr error) {
	changeID, err := publicid.New()
	if err != nil {
		return site.Result{}, site.ErrUnavailable
	}
	tx, err := store.begin(ctx, scope)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return site.Result{}, err
	}
	encoded, err := apply(tx, changeID)
	if err != nil {
		return site.Result{}, siteDatabaseError(err)
	}
	var record siteChangeRecord
	if err := decodeSiteJSON([]byte(encoded), &record); err != nil ||
		(record.Changed && (record.NetworkRevision <= 0 || record.RouteRevision <= 0)) {
		return site.Result{}, site.ErrInvalid
	}
	saved, err := record.Site.site(deleted)
	if err != nil || saved.ID != siteID || (record.Previous == nil) != (action == "network_site.created") {
		return site.Result{}, site.ErrInvalid
	}
	result := site.Result{Site: saved, Deleted: deleted, Changed: record.Changed}
	if record.Previous != nil {
		previous, err := record.Previous.site(false)
		if err != nil || previous.Version != expectedVersion {
			return site.Result{}, site.ErrInvalid
		}
		result.Previous = &previous
	}
	if !record.Changed {
		// Nothing changed: no evidence, no wakeup; the transaction rolls back.
		return result, nil
	}
	if err := appendSiteEvidence(ctx, tx, session, scope, correlationID, changeID, record, action, permission,
		router); err != nil {
		return site.Result{}, errors.Join(site.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return site.Result{}, errors.Join(site.ErrUnavailable, err)
	}
	committed = true
	return result, nil
}

// siteSemanticHash commits to what a Site routes: its identity, name, state,
// prefixes, translation and routers.
func siteSemanticHash(document siteDocument) ([32]byte, error) {
	type router struct {
		DeviceID string `json:"device_id"`
		Priority int    `json:"priority"`
		State    string `json:"state"`
	}
	routers := make([]router, 0, len(document.Routers))
	for _, item := range document.Routers {
		routers = append(routers, router{item.DeviceID, item.Priority, item.State})
	}
	encoded, err := json.Marshal(struct {
		SiteID     string              `json:"site_id"`
		Name       string              `json:"name"`
		State      string              `json:"state"`
		Prefixes   []string            `json:"prefixes"`
		Masquerade bool                `json:"masquerade"`
		Failback   bool                `json:"failback"`
		Probes     []siteProbeDocument `json:"probes"`
		Routers    []router            `json:"routers"`
	}{document.ID, document.Name, document.State, document.Prefixes, document.Masquerade, document.Failback,
		document.Probes, routers})
	return sha256.Sum256(encoded), err
}

func appendSiteEvidence(ctx context.Context, tx accountSessionTransaction, session accountsession.Session,
	scope network.Scope, correlationID, changeID publicid.ID, record siteChangeRecord, action, permission string,
	router node.ID) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return site.ErrInvalid
	}
	var before [32]byte
	var beforeArgument any
	var err error
	if record.Previous != nil {
		if before, err = siteSemanticHash(*record.Previous); err != nil {
			return err
		}
		beforeArgument = before[:]
	}
	after, err := siteSemanticHash(record.Site)
	if err != nil {
		return err
	}
	binding := ""
	if record.RoleBindingID != nil {
		binding = *record.RoleBindingID
	}
	networkID := scope.NetworkID().String()
	audited := siteAuditPayload{
		NetworkID: networkID, SessionID: session.ID().String(), RoleBindingID: binding, SiteID: record.Site.ID,
		Name: record.Site.Name, Prefixes: record.Site.Prefixes, Masquerade: record.Site.Masquerade,
		Routers: len(record.Site.Routers),
	}
	if record.Previous != nil {
		if record.Previous.Name != record.Site.Name {
			audited.PreviousName = record.Previous.Name
		}
		if !slices.Equal(record.Previous.Prefixes, record.Site.Prefixes) {
			audited.PreviousPrefixes = record.Previous.Prefixes
		}
	}
	if router.IsValid() {
		audited.Router = siteRouterChange(router, record)
	}
	payload, err := json.Marshal(audited)
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		NetworkID       string `json:"network_id"`
		SiteID          string `json:"site_id"`
		Version         int64  `json:"version"`
		NetworkRevision int64  `json:"network_revision"`
		RouteRevision   int64  `json:"route_revision"`
	}{networkID, record.Site.ID, record.Site.Version, record.NetworkRevision, record.RouteRevision})
	if err != nil {
		return err
	}
	eventID, err := publicid.New()
	if err != nil {
		return err
	}
	outboxID, err := publicid.New()
	if err != nil {
		return err
	}
	siteID, err := publicid.Parse(record.Site.ID)
	if err != nil {
		return site.ErrInvalid
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "network_site", AggregateID: siteID, AggregateVersion: record.Site.Version,
		NetworkRevision: record.NetworkRevision, ActorPrincipalID: principal, Action: action,
		Permission: permission, CorrelationID: correlationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendSiteEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], record.Site.ID, record.Site.Version, record.NetworkRevision,
		principal.String(), action, permission, correlationID.String(), beforeArgument, after[:], payload,
		outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return site.ErrInvalid
	}
	return nil
}

type siteAuditPayload struct {
	NetworkID        string           `json:"network_id"`
	SessionID        string           `json:"session_id"`
	RoleBindingID    string           `json:"role_binding_id,omitempty"`
	SiteID           string           `json:"site_id"`
	Name             string           `json:"display_name"`
	PreviousName     string           `json:"previous_display_name,omitempty"`
	Prefixes         []string         `json:"prefixes"`
	PreviousPrefixes []string         `json:"previous_prefixes,omitempty"`
	Masquerade       bool             `json:"masquerade"`
	Routers          int              `json:"router_count"`
	Router           *siteRouterAudit `json:"router,omitempty"`
}

// siteRouterAudit names the Device a router change is about, with its
// priority and state before and after (absent when it was not a router or
// no longer is).
type siteRouterAudit struct {
	DeviceID         string `json:"device_id"`
	Priority         *int   `json:"priority,omitempty"`
	State            string `json:"state,omitempty"`
	PreviousPriority *int   `json:"previous_priority,omitempty"`
	PreviousState    string `json:"previous_state,omitempty"`
}

func siteRouterChange(device node.ID, record siteChangeRecord) *siteRouterAudit {
	change := &siteRouterAudit{DeviceID: device.String()}
	for _, item := range record.Site.Routers {
		if item.DeviceID == change.DeviceID {
			priority := item.Priority
			change.Priority, change.State = &priority, item.State
		}
	}
	if record.Previous != nil {
		for _, item := range record.Previous.Routers {
			if item.DeviceID == change.DeviceID {
				priority := item.Priority
				change.PreviousPriority, change.PreviousState = &priority, item.State
			}
		}
	}
	return change
}
