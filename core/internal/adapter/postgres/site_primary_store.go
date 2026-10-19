package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/core/internal/domain/site/election"
)

var (
	// ErrInvalidSitePrimary reports unsafe construction or input.
	ErrInvalidSitePrimary = errors.New("invalid postgres Site election")
	// ErrSitePrimary classifies a failed read or election.
	ErrSitePrimary = errors.New("elect postgres Site primary")
	// ErrSitePrimaryCommitUnknown forbids retry until state is re-read.
	ErrSitePrimaryCommitUnknown = errors.New("postgres Site election commit outcome unknown")
)

const (
	listSiteElectionsSQL     = `SELECT mesh_ops.list_site_elections_v1($1::UUID,$2::UUID,$3::INTEGER)`
	prepareSitePrimarySQL    = `SELECT mesh_ops.prepare_site_primary_v1($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::UUID)`
	finalizeSitePrimarySQL   = `SELECT mesh_ops.finalize_site_primary_v1($1::UUID,$2::UUID,$3::UUID,$4::TEXT,$5::JSONB)`
	sitePrimaryAction        = "site.primary_changed"
	sitePrimaryPermission    = "system.reconcile"
	sitePrimaryAggregate     = "site_primary"
	sitePrimaryOutboxClass   = "network.revision.advanced"
	sitePrimaryMaximumBytes  = 1 << 20
	sitePrimaryMaximumRouter = 64
)

// SitePrimaryStore reads Sites to elect for and records their primaries,
// through a worker pool only. It holds no cache, sticky transaction or
// goroutine.
type SitePrimaryStore struct {
	database outboxDatabase
}

var (
	_ election.Facts    = (*SitePrimaryStore)(nil)
	_ election.Recorder = (*SitePrimaryStore)(nil)
)

// NewSitePrimaryStore rejects non-worker pools before any effect.
func NewSitePrimaryStore(pool *Pool) (*SitePrimaryStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidSitePrimary
	}
	return &SitePrimaryStore{database: pool.outboxDatabase}, nil
}

// List reads one page of Sites with routers after a Site in one read-only
// transaction.
func (store *SitePrimaryStore) List(ctx context.Context, installation deployment.ID, after site.ID, limit int,
) (result election.Page, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || limit < 1 || limit > 64 {
		return election.Page{}, ErrInvalidSitePrimary
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return election.Page{}, errors.Join(ErrSitePrimary, err)
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	committed := false
	if transaction != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			}
			if resultErr != nil {
				result = election.Page{}
			}
		}()
	}
	if beginErr != nil {
		return election.Page{}, errors.Join(ErrSitePrimary, beginErr)
	}
	if transaction == nil {
		return election.Page{}, ErrSitePrimary
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "3000", "1000", "5000"); err != nil {
		return election.Page{}, errors.Join(ErrSitePrimary, err)
	}
	var afterSite any
	if after.IsValid() {
		afterSite = after.String()
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, listSiteElectionsSQL, installation.String(), afterSite, limit).Scan(&encoded); err != nil {
		return election.Page{}, errors.Join(ErrSitePrimary, err)
	}
	page, err := decodeSiteElectionPage(encoded, after, limit)
	if err != nil {
		return election.Page{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return election.Page{}, errors.Join(ErrSitePrimary, err)
	}
	committed = true
	return page, nil
}

type siteElectionRecord struct {
	SiteID      string               `json:"site_id"`
	WorkspaceID string               `json:"workspace_id"`
	NetworkID   string               `json:"network_id"`
	Failback    *bool                `json:"failback"`
	Primary     *string              `json:"primary_device_id"`
	Generation  *int64               `json:"generation"`
	Routers     []siteElectionRouter `json:"routers"`
}

type siteElectionRouter struct {
	DeviceID       string `json:"device_id"`
	Priority       *int   `json:"priority"`
	State          string `json:"state"`
	Live           *bool  `json:"live"`
	WorkspaceOwned *bool  `json:"workspace_owned"`
	Covers         *bool  `json:"covers"`
}

// decodeSiteElectionPage accepts exactly the documented shape: Sites in
// increasing order after after, routers in priority order.
func decodeSiteElectionPage(encoded []byte, after site.ID, limit int) (election.Page, error) {
	if len(encoded) == 0 || len(encoded) > sitePrimaryMaximumBytes {
		return election.Page{}, ErrSitePrimary
	}
	var record struct {
		Items []siteElectionRecord `json:"items"`
		Done  *bool                `json:"done"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Items == nil || record.Done == nil ||
		len(record.Items) > limit || (!*record.Done && len(record.Items) != limit) {
		return election.Page{}, ErrSitePrimary
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return election.Page{}, ErrSitePrimary
	}
	page := election.Page{Done: *record.Done, Sites: make([]election.SiteFacts, 0, len(record.Items))}
	previous := ""
	if after.IsValid() {
		previous = after.String()
	}
	for _, item := range record.Items {
		// Canonical UUID text sorts as the UUIDs do.
		facts, ok := decodeSiteElection(item)
		if !ok || (previous != "" && facts.Site.String() <= previous) {
			return election.Page{}, ErrSitePrimary
		}
		previous = facts.Site.String()
		page.Sites = append(page.Sites, facts)
	}
	return page, nil
}

func decodeSiteElection(item siteElectionRecord) (election.SiteFacts, bool) {
	id, err := site.ParseID(item.SiteID)
	if err != nil || item.Failback == nil || item.Generation == nil || *item.Generation < 0 ||
		len(item.Routers) == 0 || len(item.Routers) > sitePrimaryMaximumRouter || item.WorkspaceID == "" ||
		item.NetworkID == "" {
		return election.SiteFacts{}, false
	}
	facts := election.SiteFacts{Site: id, Failback: *item.Failback, Generation: *item.Generation,
		Routers: make([]election.RouterFacts, 0, len(item.Routers))}
	if item.Primary != nil {
		if facts.Primary, err = node.ParseID(*item.Primary); err != nil {
			return election.SiteFacts{}, false
		}
	}
	seen := map[node.ID]struct{}{}
	for index, router := range item.Routers {
		device, err := node.ParseID(router.DeviceID)
		if err != nil || router.Priority == nil || router.Live == nil || router.WorkspaceOwned == nil ||
			router.Covers == nil || (router.State != "active" && router.State != "draining") {
			return election.SiteFacts{}, false
		}
		if _, repeated := seen[device]; repeated {
			return election.SiteFacts{}, false
		}
		seen[device] = struct{}{}
		if index > 0 {
			before := item.Routers[index-1]
			if *before.Priority > *router.Priority ||
				(*before.Priority == *router.Priority && before.DeviceID >= router.DeviceID) {
				return election.SiteFacts{}, false
			}
		}
		facts.Routers = append(facts.Routers, election.RouterFacts{Device: device, Priority: *router.Priority,
			Draining: router.State == "draining", Live: *router.Live, WorkspaceOwned: *router.WorkspaceOwned,
			Covers: *router.Covers})
	}
	return facts, true
}

// Record prepares the decision and locks the audit head, hashes the evidence
// locally, then finalizes and commits in one bounded transaction. False
// means the decision was made on an older state or changes nothing. An
// unknown commit outcome is reported and never retried here; the next sweep
// re-reads committed state.
func (store *SitePrimaryStore) Record(ctx context.Context, installation deployment.ID, decision election.Decision,
) (changed bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !decision.Site.IsValid() ||
		decision.ExpectedGeneration < 0 || !validElectionReason(decision.Reason) {
		return false, ErrInvalidSitePrimary
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrSitePrimary, err)
	}
	var ids [3]publicid.ID
	for index := range ids {
		fresh, err := freshPublicID()
		if err != nil {
			return false, errors.Join(ErrSitePrimary, err)
		}
		ids[index] = fresh
	}
	change := ids[0]
	transaction, beginErr := store.database.Begin(ctx, false)
	committed := false
	if transaction != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			}
			if resultErr != nil {
				changed = false
			}
		}()
	}
	if beginErr != nil {
		return false, errors.Join(ErrSitePrimary, beginErr)
	}
	if transaction == nil {
		return false, ErrSitePrimary
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "5000", "1000", "10000"); err != nil {
		return false, errors.Join(ErrSitePrimary, err)
	}
	var device any
	if decision.Primary.IsValid() {
		device = decision.Primary.String()
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, prepareSitePrimarySQL, installation.String(), decision.Site.String(),
		decision.ExpectedGeneration, device, decision.Reason, change.String()).Scan(&encoded); err != nil {
		return false, errors.Join(ErrSitePrimary, err)
	}
	proof, err := decodeSitePrimaryProof(encoded, decision, change)
	if err != nil {
		return false, err
	}
	if !proof.Changed {
		return false, nil // rolled back by the deferred function
	}
	event, err := hashSitePrimaryEvent(proof, change, ids[1], ids[2])
	if err != nil {
		return false, errors.Join(ErrSitePrimary, err)
	}
	var count int
	if err := transaction.QueryRow(ctx, finalizeSitePrimarySQL, installation.String(), decision.Site.String(),
		change.String(), decision.Reason, event).Scan(&count); err != nil {
		return false, errors.Join(ErrSitePrimary, err)
	}
	if count != 1 {
		return false, ErrSitePrimary
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrSitePrimary, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrSitePrimary, ErrSitePrimaryCommitUnknown, err)
	}
	committed = true
	return true, nil
}

func validElectionReason(reason string) bool {
	switch reason {
	case election.ReasonElected, election.ReasonFailover, election.ReasonFailback, election.ReasonDegraded,
		election.ReasonNone:
		return true
	default:
		return false
	}
}

type sitePrimaryProof struct {
	Changed          bool                        `json:"changed"`
	TransactionID    string                      `json:"transaction_id"`
	ChangeID         string                      `json:"change_id"`
	SiteID           string                      `json:"site_id"`
	Generation       int64                       `json:"generation"`
	AggregateVersion int64                       `json:"aggregate_version"`
	Event            *resourceRetirementEvidence `json:"event"`
}

// decodeSitePrimaryProof accepts exactly the unchanged answer, or one
// election of the requested Site under this change, one generation on.
func decodeSitePrimaryProof(encoded []byte, decision election.Decision, change publicid.ID) (sitePrimaryProof, error) {
	if len(encoded) == 0 || len(encoded) > resourceRetirementMaximumBytes {
		return sitePrimaryProof{}, ErrSitePrimary
	}
	var proof sitePrimaryProof
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return sitePrimaryProof{}, ErrSitePrimary
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return sitePrimaryProof{}, ErrSitePrimary
	}
	if !proof.Changed {
		if proof.Event != nil || proof.TransactionID != "" || proof.ChangeID != "" || proof.SiteID != "" ||
			proof.Generation != 0 || proof.AggregateVersion != 0 {
			return sitePrimaryProof{}, ErrSitePrimary
		}
		return proof, nil
	}
	transaction, err := strconv.ParseInt(proof.TransactionID, 10, 64)
	if err != nil || transaction <= 0 || proof.ChangeID != change.String() || proof.SiteID != decision.Site.String() ||
		proof.Generation != decision.ExpectedGeneration+1 || proof.AggregateVersion < 1 || proof.Event == nil ||
		!validResourceRetirementEvidence(*proof.Event) {
		return sitePrimaryProof{}, ErrSitePrimary
	}
	return proof, nil
}

// hashSitePrimaryEvent binds the event to fresh event and outbox ids. The
// system actor and correlation are zero, as in other reconcilers.
func hashSitePrimaryEvent(proof sitePrimaryProof, change, eventID, outboxID publicid.ID) ([]byte, error) {
	if proof.Event == nil {
		return nil, ErrSitePrimary
	}
	aggregateID, err := publicid.Parse(proof.SiteID)
	if err != nil {
		return nil, ErrSitePrimary
	}
	event := *proof.Event
	previous, err := hex.DecodeString(event.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return nil, ErrSitePrimary
	}
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: change,
		AggregateKind: sitePrimaryAggregate, AggregateID: aggregateID, AggregateVersion: proof.AggregateVersion,
		NetworkRevision: event.NetworkRevision, Action: sitePrimaryAction, Permission: sitePrimaryPermission,
		AuditPayloadHash:  sha256.Sum256([]byte(event.AuditPayload)),
		OutboxEventClass:  sitePrimaryOutboxClass,
		OutboxPayloadHash: sha256.Sum256([]byte(event.OutboxPayload)),
	})
	if err != nil {
		return nil, err
	}
	event.EventID, event.OutboxID, event.EventHash = eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])
	return json.Marshal(event)
}
