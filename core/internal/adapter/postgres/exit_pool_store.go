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
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const maximumExitPoolDocumentBytes = 1 << 20

const listExitPoolsSQL = `SELECT mesh_ops.list_exit_pools_v1(` + sessionArguments + `,$10::UUID,$11::UUID,
 NULLIF($12::TEXT,'')::UUID,$13::INTEGER)::TEXT`

const readExitPoolSQL = `SELECT mesh_ops.read_exit_pool_v1(` + sessionArguments + `,$10::UUID,$11::UUID,$12::UUID)::TEXT`

const changeExitPoolSQL = `SELECT mesh_ops.change_exit_pool_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::UUID,$14::BIGINT,$15::TEXT,$16::BOOLEAN,$17::BOOLEAN,$18::INTEGER,
 $19::INET[],$20::JSONB,$21::INTEGER,$22::UUID)::TEXT`

const changeExitNodeSQL = `SELECT mesh_ops.change_exit_node_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::UUID,$14::BIGINT,$15::UUID,$16::INTEGER,$17::TEXT,$18::INTEGER,
 $19::UUID,$20::UUID)::TEXT`

const appendExitPoolEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network_exit_pool',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,$12::TEXT,
 $13::UUID,$14::BYTEA,$15::BYTEA,$16::JSONB,'network.revision.advanced',$17::JSONB)`

// ExitPoolStore reads and changes the Exit Pools of a Network through the
// runtime pool. Each change commits with its evidence on the Network stream
// and wakes map sessions through the revision outbox.
type ExitPoolStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ exitpool.Store = (*ExitPoolStore)(nil)

// NewExitPoolStore uses the runtime pool.
func NewExitPoolStore(pool *Pool, options AccountSessionOptions) (*ExitPoolStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, exitpool.ErrInvalid
	}
	return &ExitPoolStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func exitPoolDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return exitpool.ErrForbidden
		case "P0002":
			return exitpool.ErrNotFound
		case "40001":
			return exitpool.ErrVersionConflict
		case "MTX01":
			return exitpool.ErrNameTaken
		case "MTX02":
			return exitpool.ErrPoolLimit
		case "MTX03":
			return exitpool.ErrNodeLimit
		case "MTX04":
			return exitpool.ErrNodeNotEligible
		case "MTX05":
			return exitpool.ErrNodeInOtherPool
		case "MTX06":
			return exitpool.ErrInUse
		case "22023", "22P02", "23514":
			return exitpool.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return exitpool.ErrForbidden
	}
	return errors.Join(exitpool.ErrUnavailable, err)
}

// begin starts one unit of work in the Network scope.
func (store *ExitPoolStore) begin(ctx context.Context, scope network.Scope) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, exitpool.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(exitpool.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(exitpool.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return tx, exitPoolDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return tx, exitpool.ErrForbidden
	}
	return tx, nil
}

func decodeExitPoolJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumExitPoolDocumentBytes {
		return exitpool.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return exitpool.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return exitpool.ErrInvalid
	}
	return nil
}

type exitProbeDocument struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type exitNodeDocument struct {
	DeviceID    string    `json:"device_id"`
	DeviceName  string    `json:"device_name"`
	DeviceState string    `json:"device_state"`
	Ownership   string    `json:"ownership"`
	Offered     bool      `json:"offered"`
	Priority    int       `json:"priority"`
	State       string    `json:"state"`
	AddedAt     time.Time `json:"added_at"`
}

type exitPoolDocument struct {
	ID                   string              `json:"pool_id"`
	Name                 string              `json:"name"`
	Failback             bool                `json:"failback"`
	SMTPAllowed          bool                `json:"smtp_allowed"`
	ConntrackPerConsumer int                 `json:"conntrack_per_consumer"`
	DNSUpstreams         []string            `json:"dns_upstreams"`
	Probes               []exitProbeDocument `json:"probes"`
	State                string              `json:"state"`
	Version              int64               `json:"version"`
	CreatedAt            time.Time           `json:"created_at"`
	UpdatedAt            time.Time           `json:"updated_at"`
	Nodes                []exitNodeDocument  `json:"nodes"`
}

var exitNodeStates = map[string]exitpool.NodeState{"active": exitpool.NodeActive, "draining": exitpool.NodeDraining}

func (document exitPoolDocument) pool(allowDeleted bool) (exitpool.Pool, error) {
	id, err := exitpool.ParseID(document.ID)
	if err != nil || (document.State != "active" && (!allowDeleted || document.State != "deleted")) ||
		document.Version <= 0 || document.CreatedAt.IsZero() || document.UpdatedAt.Before(document.CreatedAt) {
		return exitpool.Pool{}, exitpool.ErrInvalid
	}
	stored := exitpool.Pool{
		ID: id, Version: document.Version, CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
		Definition: exitpool.Definition{
			Name: document.Name, Failback: document.Failback, SMTPAllowed: document.SMTPAllowed,
			ConntrackPerConsumer: document.ConntrackPerConsumer,
			DNSUpstreams:         make([]netip.Addr, 0, len(document.DNSUpstreams)),
			Probes:               make([]exitpool.Probe, 0, len(document.Probes)),
		},
		Nodes: make([]exitpool.Node, 0, len(document.Nodes)),
	}
	for _, text := range document.DNSUpstreams {
		address, err := netip.ParseAddr(text)
		if err != nil {
			return exitpool.Pool{}, exitpool.ErrInvalid
		}
		stored.DNSUpstreams = append(stored.DNSUpstreams, address)
	}
	for _, item := range document.Probes {
		address, err := netip.ParseAddr(item.Address)
		if err != nil {
			return exitpool.Pool{}, exitpool.ErrInvalid
		}
		stored.Probes = append(stored.Probes, exitpool.Probe{Address: address, Port: item.Port})
	}
	for _, item := range document.Nodes {
		exitNode, err := item.node()
		if err != nil {
			return exitpool.Pool{}, err
		}
		stored.Nodes = append(stored.Nodes, exitNode)
	}
	return stored, nil
}

func (document exitNodeDocument) node() (exitpool.Node, error) {
	deviceID, err := node.ParseID(document.DeviceID)
	if err != nil || document.AddedAt.IsZero() {
		return exitpool.Node{}, exitpool.ErrInvalid
	}
	exitNode := exitpool.Node{
		NodeAssignment: exitpool.NodeAssignment{DeviceID: deviceID, Priority: document.Priority,
			State: exitNodeStates[document.State]},
		DeviceName: document.DeviceName,
		Offered:    document.Offered,
		Eligible:   exitpool.Eligible(document.DeviceState, document.Ownership, document.Offered),
		AddedAt:    document.AddedAt,
	}
	if exitNode.Validate() != nil {
		return exitpool.Node{}, exitpool.ErrInvalid
	}
	return exitNode, nil
}

// List authorizes route.read and returns one page of active pools.
func (store *ExitPoolStore) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	after exitpool.ID, limit int) (exitpool.Listing, error) {
	if !session.IsValid() || !scope.IsValid() || limit < 1 || limit > exitpool.MaximumPage {
		return exitpool.Listing{}, exitpool.ErrInvalid
	}
	afterText := ""
	if after.IsValid() {
		afterText = after.String()
	}
	var envelope struct {
		Pools     []exitPoolDocument `json:"pools"`
		HasMore   bool               `json:"has_more"`
		CanManage bool               `json:"can_manage"`
		CanDelete bool               `json:"can_delete"`
	}
	if err := store.read(ctx, session, scope, listExitPoolsSQL, &envelope, afterText, limit); err != nil {
		return exitpool.Listing{}, err
	}
	if envelope.Pools == nil || len(envelope.Pools) > limit {
		return exitpool.Listing{}, exitpool.ErrInvalid
	}
	listing := exitpool.Listing{Pools: make([]exitpool.Pool, 0, len(envelope.Pools)), HasMore: envelope.HasMore,
		Abilities: exitpool.Abilities{CanManage: envelope.CanManage, CanDelete: envelope.CanDelete}}
	for _, document := range envelope.Pools {
		stored, err := document.pool(false)
		if err != nil {
			return exitpool.Listing{}, err
		}
		listing.Pools = append(listing.Pools, stored)
	}
	return listing, nil
}

// Read authorizes route.read and returns one active pool.
func (store *ExitPoolStore) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	id exitpool.ID) (exitpool.Reading, error) {
	if !session.IsValid() || !scope.IsValid() || !id.IsValid() {
		return exitpool.Reading{}, exitpool.ErrInvalid
	}
	var envelope struct {
		Pool      exitPoolDocument `json:"pool"`
		CanManage bool             `json:"can_manage"`
		CanDelete bool             `json:"can_delete"`
	}
	if err := store.read(ctx, session, scope, readExitPoolSQL, &envelope, id.String()); err != nil {
		return exitpool.Reading{}, err
	}
	stored, err := envelope.Pool.pool(false)
	if err != nil || stored.ID != id {
		return exitpool.Reading{}, exitpool.ErrInvalid
	}
	return exitpool.Reading{Pool: stored, Abilities: exitpool.Abilities{CanManage: envelope.CanManage,
		CanDelete: envelope.CanDelete}}, nil
}

// read runs one read function in its own transaction and decodes its result.
func (store *ExitPoolStore) read(ctx context.Context, session accountsession.Session, scope network.Scope,
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
		return exitPoolDatabaseError(err)
	}
	return decodeExitPoolJSON([]byte(encoded), target)
}

type exitPoolChangeRecord struct {
	Pool            exitPoolDocument  `json:"pool"`
	Previous        *exitPoolDocument `json:"previous"`
	Changed         bool              `json:"changed"`
	NetworkRevision int64             `json:"network_revision"`
	RouteRevision   int64             `json:"route_revision"`
	RoleBindingID   *string           `json:"role_binding_id"`
}

func exitProbesJSON(probes []exitpool.Probe) ([]byte, error) {
	documents := make([]exitProbeDocument, 0, len(probes))
	for _, probe := range probes {
		documents = append(documents, exitProbeDocument{Address: probe.Address.String(), Port: probe.Port})
	}
	return json.Marshal(documents)
}

func addressTexts(addresses []netip.Addr) []string {
	texts := make([]string, 0, len(addresses))
	for _, address := range addresses {
		texts = append(texts, address.String())
	}
	return texts
}

// Change authorizes route.approve (route.withdraw to delete), applies the
// change and commits it with its evidence.
func (store *ExitPoolStore) Change(ctx context.Context, change exitpool.Change) (exitpool.Result, error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.PoolID.IsValid() ||
		!change.CorrelationID.IsValid() {
		return exitpool.Result{}, exitpool.ErrInvalid
	}
	var expected, name, failback, smtp, conntrack, upstreams, probes, limit any
	if change.Operation != exitpool.OperationCreate {
		expected = change.ExpectedVersion
	} else {
		limit = change.PoolLimit
	}
	if change.Operation != exitpool.OperationDelete {
		encodedProbes, err := exitProbesJSON(change.Definition.Probes)
		if err != nil {
			return exitpool.Result{}, exitpool.ErrInvalid
		}
		definition := change.Definition
		name, failback, smtp, conntrack = definition.Name, definition.Failback, definition.SMTPAllowed,
			definition.ConntrackPerConsumer
		upstreams, probes = addressTexts(definition.DNSUpstreams), encodedProbes
	}
	permission := "route.approve"
	if change.Operation == exitpool.OperationDelete {
		permission = "route.withdraw"
	}
	return store.commit(ctx, change.Session, change.Scope, change.CorrelationID, exitPoolAction(change.Operation),
		permission, change.Operation == exitpool.OperationDelete, change.PoolID, change.ExpectedVersion, node.ID{},
		func(tx accountSessionTransaction, changeID publicid.ID) (string, error) {
			var encoded string
			err := tx.QueryRow(ctx, changeExitPoolSQL, append(sessionQueryArguments(change.Session),
				change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), string(change.Operation),
				change.PoolID.String(), expected, name, failback, smtp, conntrack, upstreams, probes, limit,
				changeID.String())...).Scan(&encoded)
			return encoded, err
		})
}

// ChangeNode authorizes route.approve (route.withdraw to remove) and adds,
// changes or removes an exit node.
func (store *ExitPoolStore) ChangeNode(ctx context.Context, change exitpool.NodeChange) (exitpool.Result, error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.PoolID.IsValid() ||
		!change.Assignment.DeviceID.IsValid() || change.ExpectedVersion <= 0 || !change.CorrelationID.IsValid() {
		return exitpool.Result{}, exitpool.ErrInvalid
	}
	var priority, state, limit, rowID any
	action, permission := "network_exit_pool.node_removed", "route.withdraw"
	if change.Operation == exitpool.NodePut {
		if !change.NodeRowID.IsValid() {
			return exitpool.Result{}, exitpool.ErrInvalid
		}
		priority, limit, rowID = change.Assignment.Priority, change.NodeLimit, change.NodeRowID.String()
		state = map[exitpool.NodeState]string{exitpool.NodeActive: "active",
			exitpool.NodeDraining: "draining"}[change.Assignment.State]
		action, permission = "network_exit_pool.node_set", "route.approve"
	}
	return store.commit(ctx, change.Session, change.Scope, change.CorrelationID, action, permission, false,
		change.PoolID, change.ExpectedVersion, change.Assignment.DeviceID,
		func(tx accountSessionTransaction, changeID publicid.ID) (string, error) {
			var encoded string
			err := tx.QueryRow(ctx, changeExitNodeSQL, append(sessionQueryArguments(change.Session),
				change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), string(change.Operation),
				change.PoolID.String(), change.ExpectedVersion, change.Assignment.DeviceID.String(), priority, state,
				limit, rowID, changeID.String())...).Scan(&encoded)
			return encoded, err
		})
}

func exitPoolAction(operation exitpool.Operation) string {
	switch operation {
	case exitpool.OperationCreate:
		return "network_exit_pool.created"
	case exitpool.OperationUpdate:
		return "network_exit_pool.updated"
	default:
		return "network_exit_pool.deleted"
	}
}

// commit runs one change function, checks its record and appends evidence.
func (store *ExitPoolStore) commit(ctx context.Context, session accountsession.Session, scope network.Scope,
	correlationID publicid.ID, action, permission string, deleted bool, poolID exitpool.ID, expectedVersion int64,
	device node.ID, apply func(accountSessionTransaction, publicid.ID) (string, error),
) (_ exitpool.Result, resultErr error) {
	changeID, err := publicid.New()
	if err != nil {
		return exitpool.Result{}, exitpool.ErrUnavailable
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
		return exitpool.Result{}, err
	}
	encoded, err := apply(tx, changeID)
	if err != nil {
		return exitpool.Result{}, exitPoolDatabaseError(err)
	}
	var record exitPoolChangeRecord
	if err := decodeExitPoolJSON([]byte(encoded), &record); err != nil ||
		(record.Changed && (record.NetworkRevision <= 0 || record.RouteRevision <= 0)) {
		return exitpool.Result{}, exitpool.ErrInvalid
	}
	saved, err := record.Pool.pool(deleted)
	if err != nil || saved.ID != poolID || (record.Previous == nil) != (action == "network_exit_pool.created") {
		return exitpool.Result{}, exitpool.ErrInvalid
	}
	result := exitpool.Result{Pool: saved, Deleted: deleted, Changed: record.Changed}
	if record.Previous != nil {
		previous, err := record.Previous.pool(false)
		if err != nil || previous.Version != expectedVersion {
			return exitpool.Result{}, exitpool.ErrInvalid
		}
		result.Previous = &previous
	}
	if !record.Changed {
		// Nothing changed: no evidence, no wakeup; the transaction rolls back.
		return result, nil
	}
	if err := appendExitPoolEvidence(ctx, tx, session, scope, correlationID, changeID, record, action, permission,
		device); err != nil {
		return exitpool.Result{}, errors.Join(exitpool.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return exitpool.Result{}, errors.Join(exitpool.ErrUnavailable, err)
	}
	committed = true
	return result, nil
}

// exitPoolSemanticHash commits to what a pool decides: its identity, name,
// state, options and exit nodes.
func exitPoolSemanticHash(document exitPoolDocument) ([32]byte, error) {
	type exitNode struct {
		DeviceID string `json:"device_id"`
		Priority int    `json:"priority"`
		State    string `json:"state"`
	}
	nodes := make([]exitNode, 0, len(document.Nodes))
	for _, item := range document.Nodes {
		nodes = append(nodes, exitNode{item.DeviceID, item.Priority, item.State})
	}
	encoded, err := json.Marshal(struct {
		PoolID               string              `json:"pool_id"`
		Name                 string              `json:"name"`
		State                string              `json:"state"`
		Failback             bool                `json:"failback"`
		SMTPAllowed          bool                `json:"smtp_allowed"`
		ConntrackPerConsumer int                 `json:"conntrack_per_consumer"`
		DNSUpstreams         []string            `json:"dns_upstreams"`
		Probes               []exitProbeDocument `json:"probes"`
		Nodes                []exitNode          `json:"nodes"`
	}{document.ID, document.Name, document.State, document.Failback, document.SMTPAllowed,
		document.ConntrackPerConsumer, document.DNSUpstreams, document.Probes, nodes})
	return sha256.Sum256(encoded), err
}

type exitPoolAuditPayload struct {
	NetworkID            string             `json:"network_id"`
	SessionID            string             `json:"session_id"`
	RoleBindingID        string             `json:"role_binding_id,omitempty"`
	PoolID               string             `json:"exit_pool_id"`
	Name                 string             `json:"display_name"`
	PreviousName         string             `json:"previous_display_name,omitempty"`
	Failback             bool               `json:"failback"`
	PreviousFailback     *bool              `json:"previous_failback,omitempty"`
	SMTPAllowed          bool               `json:"smtp_allowed"`
	PreviousSMTPAllowed  *bool              `json:"previous_smtp_allowed,omitempty"`
	ConntrackPerConsumer int                `json:"conntrack_per_consumer"`
	DNSUpstreams         []string           `json:"dns_upstreams"`
	PreviousDNSUpstreams []string           `json:"previous_dns_upstreams,omitempty"`
	Probes               int                `json:"probe_count"`
	Nodes                int                `json:"exit_node_count"`
	Node                 *exitPoolNodeAudit `json:"exit_node,omitempty"`
	// RemovedNodes are the Devices a deleted pool had as exit nodes.
	RemovedNodes []string `json:"removed_exit_nodes,omitempty"`
}

// exitPoolNodeAudit names the Device an exit node change is about, with its
// priority and state before and after (absent when it was not an exit node
// or no longer is).
type exitPoolNodeAudit struct {
	DeviceID         string `json:"device_id"`
	Priority         *int   `json:"priority,omitempty"`
	State            string `json:"state,omitempty"`
	PreviousPriority *int   `json:"previous_priority,omitempty"`
	PreviousState    string `json:"previous_state,omitempty"`
}

func exitPoolNodeChange(device node.ID, record exitPoolChangeRecord) *exitPoolNodeAudit {
	change := &exitPoolNodeAudit{DeviceID: device.String()}
	for _, item := range record.Pool.Nodes {
		if item.DeviceID == change.DeviceID {
			priority := item.Priority
			change.Priority, change.State = &priority, item.State
		}
	}
	if record.Previous != nil {
		for _, item := range record.Previous.Nodes {
			if item.DeviceID == change.DeviceID {
				priority := item.Priority
				change.PreviousPriority, change.PreviousState = &priority, item.State
			}
		}
	}
	return change
}

func exitPoolAudit(session accountsession.Session, networkID string, record exitPoolChangeRecord,
	device node.ID) exitPoolAuditPayload {
	binding := ""
	if record.RoleBindingID != nil {
		binding = *record.RoleBindingID
	}
	audited := exitPoolAuditPayload{
		NetworkID: networkID, SessionID: session.ID().String(), RoleBindingID: binding, PoolID: record.Pool.ID,
		Name: record.Pool.Name, Failback: record.Pool.Failback, SMTPAllowed: record.Pool.SMTPAllowed,
		ConntrackPerConsumer: record.Pool.ConntrackPerConsumer, DNSUpstreams: record.Pool.DNSUpstreams,
		Probes: len(record.Pool.Probes), Nodes: len(record.Pool.Nodes),
	}
	if record.Previous != nil {
		if record.Previous.Name != record.Pool.Name {
			audited.PreviousName = record.Previous.Name
		}
		if record.Previous.Failback != record.Pool.Failback {
			previous := record.Previous.Failback
			audited.PreviousFailback = &previous
		}
		if record.Previous.SMTPAllowed != record.Pool.SMTPAllowed {
			previous := record.Previous.SMTPAllowed
			audited.PreviousSMTPAllowed = &previous
		}
		if record.Pool.State == "deleted" {
			for _, item := range record.Previous.Nodes {
				audited.RemovedNodes = append(audited.RemovedNodes, item.DeviceID)
			}
		}
		if !slices.Equal(record.Previous.DNSUpstreams, record.Pool.DNSUpstreams) {
			audited.PreviousDNSUpstreams = record.Previous.DNSUpstreams
		}
	}
	if device.IsValid() {
		audited.Node = exitPoolNodeChange(device, record)
	}
	return audited
}

func appendExitPoolEvidence(ctx context.Context, tx accountSessionTransaction, session accountsession.Session,
	scope network.Scope, correlationID, changeID publicid.ID, record exitPoolChangeRecord, action, permission string,
	device node.ID) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return exitpool.ErrInvalid
	}
	var before [32]byte
	var beforeArgument any
	var err error
	if record.Previous != nil {
		if before, err = exitPoolSemanticHash(*record.Previous); err != nil {
			return err
		}
		beforeArgument = before[:]
	}
	after, err := exitPoolSemanticHash(record.Pool)
	if err != nil {
		return err
	}
	networkID := scope.NetworkID().String()
	payload, err := json.Marshal(exitPoolAudit(session, networkID, record, device))
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		NetworkID       string `json:"network_id"`
		PoolID          string `json:"exit_pool_id"`
		Version         int64  `json:"version"`
		NetworkRevision int64  `json:"network_revision"`
		RouteRevision   int64  `json:"route_revision"`
	}{networkID, record.Pool.ID, record.Pool.Version, record.NetworkRevision, record.RouteRevision})
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
	poolID, err := publicid.Parse(record.Pool.ID)
	if err != nil {
		return exitpool.ErrInvalid
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "network_exit_pool", AggregateID: poolID, AggregateVersion: record.Pool.Version,
		NetworkRevision: record.NetworkRevision, ActorPrincipalID: principal, Action: action,
		Permission: permission, CorrelationID: correlationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendExitPoolEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], record.Pool.ID, record.Pool.Version, record.NetworkRevision,
		principal.String(), action, permission, correlationID.String(), beforeArgument, after[:], payload,
		outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return exitpool.ErrInvalid
	}
	return nil
}
