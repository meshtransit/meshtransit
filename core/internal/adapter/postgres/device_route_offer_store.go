package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
)

const (
	// reportDeviceRouteOfferSQL resolves the session's Network and stores the
	// offer in one statement (schema 200).
	reportDeviceRouteOfferSQL = `SELECT workspace_public_id::TEXT, network_public_id::TEXT, result::TEXT
FROM mesh_ops.report_device_route_offer_v2($1::BYTEA,$2::BYTEA,$3::CIDR[],$4::UUID)`
	// deviceRouteOfferPermission names the authority a node uses on itself.
	deviceRouteOfferPermission = "device.report_self"
)

var (
	// ErrInvalidRouteOfferStore reports a store built without its database.
	ErrInvalidRouteOfferStore = errors.New("postgres: invalid route offer store")
	// ErrRouteOfferNotFound reports a session whose Device is no longer an
	// active Device with that machine and node key.
	ErrRouteOfferNotFound = errors.New("postgres: route offer Device not found")
	// ErrRouteOfferUnavailable reports an offer that could not be stored.
	ErrRouteOfferUnavailable = errors.New("postgres: route offer unavailable")
)

// RouteOfferStore stores the subnets a Device's own configuration offers to
// forward (MTCP HostinfoReport, schema 190). Each change is recorded as
// device.route_offer_changed on the Network stream in the same transaction;
// a change of whether a router covers its Sites also advances the Network
// and wakes its maps.
type RouteOfferStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewRouteOfferStore uses the runtime pool.
func NewRouteOfferStore(pool *Pool, options AccountSessionOptions) (*RouteOfferStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, ErrInvalidRouteOfferStore
	}
	return &RouteOfferStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// ReportRouteOffer stores prefixes, canonical and sorted, as identity's
// offer and reports whether it changed. Prefixes must already be bounded and
// canonical (site.CanonicalOffer).
func (store *RouteOfferStore) ReportRouteOffer(ctx context.Context, identity control.AuthenticatedNode,
	prefixes []netip.Prefix) (bool, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return false, ErrInvalidRouteOfferStore
	}
	if !slices.Equal(prefixes, site.CanonicalOffer(prefixes)) || len(prefixes) > site.MaximumOfferedPrefixes {
		return false, ErrRouteOfferUnavailable
	}
	changeID, err := publicid.New()
	if err != nil {
		return false, ErrRouteOfferUnavailable
	}
	texts := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		texts[index] = prefix.String()
	}
	fingerprint, nodeKey := identity.MachineFingerprint(), identity.NodeKey()
	changed := false
	err = store.transact(ctx, func(tx accountSessionTransaction) error {
		if err := markSessionProven(ctx, tx, fingerprint, identity.NodeKey(), identity.Proven()); err != nil {
			return routeOfferDatabaseError(err)
		}
		var workspaceID, networkID, encoded string
		if err := tx.QueryRow(ctx, reportDeviceRouteOfferSQL, fingerprint[:], nodeKey[:], texts,
			changeID.String()).Scan(&workspaceID, &networkID, &encoded); err != nil {
			return routeOfferDatabaseError(err)
		}
		scope, err := parseLogoutScope(workspaceID, networkID)
		if err != nil {
			return ErrRouteOfferUnavailable
		}
		changed, err = appendRouteOfferEvidence(ctx, tx, scope, changeID, encoded)
		return err
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

func (store *RouteOfferStore) transact(ctx context.Context, run func(tx accountSessionTransaction) error) (
	resultErr error) {
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(ErrRouteOfferUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(ErrRouteOfferUnavailable, err)
	}
	if err := run(tx); err != nil {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(ErrRouteOfferUnavailable, err)
	}
	return nil
}

type routeOfferRecord struct {
	Changed          bool     `json:"changed"`
	MovesMaps        bool     `json:"moves_maps"`
	DeviceID         string   `json:"device_id"`
	Hostname         string   `json:"hostname"`
	Version          int64    `json:"version"`
	ActorPrincipalID string   `json:"actor_principal_id"`
	Before           []string `json:"before"`
	After            []string `json:"after"`
	NetworkRevision  int64    `json:"network_revision"`
	RouteRevision    int64    `json:"route_revision"`
}

// appendRouteOfferEvidence validates what the function returned and seals a
// change with device.route_offer_changed: with the revision wakeup that
// rebuilds the Network's maps when it changes whether a router covers its
// Sites, at the current revision (which streams ignore) otherwise.
func appendRouteOfferEvidence(ctx context.Context, tx accountSessionTransaction, scope network.Scope,
	changeID publicid.ID, encoded string) (bool, error) {
	var record routeOfferRecord
	if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
		return false, ErrRouteOfferUnavailable
	}
	if !record.Changed {
		return false, nil
	}
	deviceID, deviceErr := publicid.Parse(record.DeviceID)
	actor, actorErr := publicid.Parse(record.ActorPrincipalID)
	if deviceErr != nil || actorErr != nil || record.Version <= 0 || record.NetworkRevision <= 0 ||
		record.RouteRevision <= 0 || record.Before == nil || record.After == nil {
		return false, ErrRouteOfferUnavailable
	}
	before, beforeErr := json.Marshal(record.Before)
	after, afterErr := json.Marshal(record.After)
	if beforeErr != nil || afterErr != nil {
		return false, ErrRouteOfferUnavailable
	}
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return false, errors.Join(ErrRouteOfferUnavailable, err)
	}
	outboxClass := "device.route_offer.changed"
	if record.MovesMaps {
		outboxClass = "network.revision.advanced"
	}
	beforeHash := sha256.Sum256(before)
	event := catalogEvent{
		correlationID: changeID, changeID: changeID, aggregateKind: "device_route_advertisement",
		aggregateID: deviceID, version: record.Version, networkVersion: record.NetworkRevision,
		action: "device.route_offer_changed", permission: deviceRouteOfferPermission,
		before: &beforeHash, after: sha256.Sum256(after), actor: actor,
		payload: struct {
			NetworkID  string          `json:"network_id"`
			DeviceID   string          `json:"device_id"`
			DeviceName string          `json:"display_name"`
			MovesMaps  bool            `json:"moves_maps"`
			Before     json.RawMessage `json:"before"`
			After      json.RawMessage `json:"after"`
		}{scope.NetworkID().String(), deviceID.String(), record.Hostname, record.MovesMaps, before, after},
		outboxClass: outboxClass,
		outbox: struct {
			NetworkID       string `json:"network_id"`
			DeviceID        string `json:"device_id"`
			NetworkRevision int64  `json:"network_revision"`
			RouteRevision   int64  `json:"route_revision"`
		}{scope.NetworkID().String(), deviceID.String(), record.NetworkRevision, record.RouteRevision},
	}
	if err := appendCatalogEvent(ctx, tx, streamID, sequence, previous, event); err != nil {
		return false, errors.Join(ErrRouteOfferUnavailable, err)
	}
	return true, nil
}

func routeOfferDatabaseError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRouteOfferNotFound
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P0002", "42501":
			return ErrRouteOfferNotFound
		}
	}
	return errors.Join(ErrRouteOfferUnavailable, err)
}
