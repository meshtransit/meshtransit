package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// reportDeviceExitOfferSQL resolves the session's Network and stores whether
// the Device offers to be an exit node, in one statement (schema 203).
const reportDeviceExitOfferSQL = `SELECT workspace_public_id::TEXT, network_public_id::TEXT, result::TEXT
FROM mesh_ops.report_device_exit_offer_v2($1::BYTEA,$2::BYTEA,$3::BOOLEAN,$4::UUID)`

// ExitOfferStore stores whether a Device's own configuration offers to be an
// exit node (MTCP Hostinfo.exit_offered, schema 203). Each change is recorded
// as device.exit_offer_changed on the Network stream in the same
// transaction; a change of an exit node's offer also advances the Network
// and wakes its maps.
type ExitOfferStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewExitOfferStore uses the runtime pool.
func NewExitOfferStore(pool *Pool, options AccountSessionOptions) (*ExitOfferStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, ErrInvalidRouteOfferStore
	}
	return &ExitOfferStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// ReportExitOffer stores offered as identity's exit offer and reports
// whether it changed.
func (store *ExitOfferStore) ReportExitOffer(ctx context.Context, identity control.AuthenticatedNode,
	offered bool) (bool, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return false, ErrInvalidRouteOfferStore
	}
	changeID, err := publicid.New()
	if err != nil {
		return false, ErrRouteOfferUnavailable
	}
	fingerprint, nodeKey := identity.MachineFingerprint(), identity.NodeKey()
	changed := false
	routes := RouteOfferStore(*store)
	err = routes.transact(ctx, func(tx accountSessionTransaction) error {
		if err := markSessionProven(ctx, tx, fingerprint, identity.NodeKey(), identity.Proven()); err != nil {
			return routeOfferDatabaseError(err)
		}
		var workspaceID, networkID, encoded string
		if err := tx.QueryRow(ctx, reportDeviceExitOfferSQL, fingerprint[:], nodeKey[:], offered,
			changeID.String()).Scan(&workspaceID, &networkID, &encoded); err != nil {
			return routeOfferDatabaseError(err)
		}
		scope, err := parseLogoutScope(workspaceID, networkID)
		if err != nil {
			return ErrRouteOfferUnavailable
		}
		changed, err = appendExitOfferEvidence(ctx, tx, scope, changeID, encoded)
		return err
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

type exitOfferRecord struct {
	Changed          bool   `json:"changed"`
	MovesMaps        bool   `json:"moves_maps"`
	DeviceID         string `json:"device_id"`
	Hostname         string `json:"hostname"`
	Version          int64  `json:"version"`
	ActorPrincipalID string `json:"actor_principal_id"`
	Before           *bool  `json:"before"`
	After            *bool  `json:"after"`
	NetworkRevision  int64  `json:"network_revision"`
	RouteRevision    int64  `json:"route_revision"`
}

// appendExitOfferEvidence validates what the function returned and seals a
// change with device.exit_offer_changed: with the revision wakeup that
// rebuilds the Network's maps when the Device is an exit node, at the
// current revision (which streams ignore) otherwise.
func appendExitOfferEvidence(ctx context.Context, tx accountSessionTransaction, scope network.Scope,
	changeID publicid.ID, encoded string) (bool, error) {
	var record exitOfferRecord
	if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
		return false, ErrRouteOfferUnavailable
	}
	if !record.Changed {
		return false, nil
	}
	deviceID, deviceErr := publicid.Parse(record.DeviceID)
	actor, actorErr := publicid.Parse(record.ActorPrincipalID)
	if deviceErr != nil || actorErr != nil || record.Version <= 0 || record.NetworkRevision <= 0 ||
		record.RouteRevision <= 0 || record.Before == nil || record.After == nil || *record.Before == *record.After {
		return false, ErrRouteOfferUnavailable
	}
	before, beforeErr := json.Marshal(*record.Before)
	after, afterErr := json.Marshal(*record.After)
	if beforeErr != nil || afterErr != nil {
		return false, ErrRouteOfferUnavailable
	}
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return false, errors.Join(ErrRouteOfferUnavailable, err)
	}
	outboxClass := "device.exit_offer.changed"
	if record.MovesMaps {
		outboxClass = "network.revision.advanced"
	}
	beforeHash := sha256.Sum256(before)
	event := catalogEvent{
		correlationID: changeID, changeID: changeID, aggregateKind: "device_exit_offer",
		aggregateID: deviceID, version: record.Version, networkVersion: record.NetworkRevision,
		action: "device.exit_offer_changed", permission: deviceRouteOfferPermission,
		before: &beforeHash, after: sha256.Sum256(after), actor: actor,
		payload: struct {
			NetworkID  string `json:"network_id"`
			DeviceID   string `json:"device_id"`
			DeviceName string `json:"display_name"`
			MovesMaps  bool   `json:"moves_maps"`
			Before     bool   `json:"before"`
			After      bool   `json:"after"`
		}{scope.NetworkID().String(), deviceID.String(), record.Hostname, record.MovesMaps, *record.Before, *record.After},
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
