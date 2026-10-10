package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/key"
)

const listWorkspacePrivateInterchangesSQL = `SELECT mesh_ops.list_workspace_private_interchanges_v1(` +
	sessionArguments + `,$10::UUID)::TEXT`

const changeWorkspacePrivateInterchangeSQL = `SELECT interchange::TEXT, COALESCE(previous_interchange::TEXT,''),
 advanced_networks::TEXT,
 COALESCE(actor_binding_public_id::TEXT,''), COALESCE(actor_role_public_id::TEXT,''),
 COALESCE(actor_binding_generation,0), COALESCE(actor_membership_generation,0), COALESCE(actor_owner_generation,0)
FROM mesh_ops.change_workspace_private_interchange_v1(` + sessionArguments + `,
 $10::UUID,$11::TEXT,$12::UUID,$13::BIGINT,$14::TEXT,$15::TEXT,$16::TEXT,$17::INET,$18::INET,$19::BYTEA,
 $20::INTEGER,$21::INTEGER,$22::INTEGER,$23::UUID[],$24::UUID)`

const privateInterchangeDirectorySQL = `SELECT mesh_ops.private_interchange_directory_v1()::TEXT`

// PrivateInterchangeStore reads and changes a Workspace's Private
// Interchange relays through the runtime pool. Each change commits with its
// evidence on the Workspace stream and a wake event on every Network whose
// relays changed.
type PrivateInterchangeStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ interchange.Store = (*PrivateInterchangeStore)(nil)

// NewPrivateInterchangeStore uses the runtime pool.
func NewPrivateInterchangeStore(pool *Pool, options AccountSessionOptions) (*PrivateInterchangeStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, interchange.ErrInvalid
	}
	return &PrivateInterchangeStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// privateInterchangeDocument is one relay as PostgreSQL returns it.
type privateInterchangeDocument struct {
	ID         string    `json:"interchange_id"`
	Name       string    `json:"name"`
	RegionID   int       `json:"region_id"`
	RegionCode string    `json:"region_code"`
	HostName   string    `json:"host_name"`
	IPv4       *string   `json:"ipv4"`
	IPv6       *string   `json:"ipv6"`
	RelayKey   string    `json:"relay_key"`
	UDPPort    int       `json:"udp_port"`
	TLSPort    int       `json:"tls_port"`
	STUNPort   int       `json:"stun_port"`
	NetworkIDs []string  `json:"network_ids"`
	Version    int64     `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	State      string    `json:"state,omitempty"`
}

func (document privateInterchangeDocument) interchange() (interchange.Interchange, error) {
	id, err := publicid.Parse(document.ID)
	if err != nil || document.RegionID < 1000 || document.RegionID > 64999 {
		return interchange.Interchange{}, interchange.ErrInvalid
	}
	spec, err := document.spec()
	if err != nil {
		return interchange.Interchange{}, err
	}
	result := interchange.Interchange{ID: id, RegionID: uint16(document.RegionID), Spec: spec,
		Version: document.Version, CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt}
	if !result.IsValid() {
		return interchange.Interchange{}, interchange.ErrInvalid
	}
	return result, nil
}

func (document privateInterchangeDocument) spec() (interchange.Spec, error) {
	raw, err := hex.DecodeString(document.RelayKey)
	if err != nil || len(raw) != key.Size {
		return interchange.Spec{}, interchange.ErrInvalid
	}
	spec := interchange.Spec{Name: document.Name, RegionCode: document.RegionCode, HostName: document.HostName,
		RelayKey: key.RelayPublic(raw)}
	for _, port := range []struct {
		value  int
		target *uint16
	}{{document.UDPPort, &spec.UDPPort}, {document.TLSPort, &spec.TLSPort}, {document.STUNPort, &spec.STUNPort}} {
		if port.value < 0 || port.value > 65535 {
			return interchange.Spec{}, interchange.ErrInvalid
		}
		*port.target = uint16(port.value)
	}
	for _, address := range []struct {
		text   *string
		target *netip.Addr
	}{{document.IPv4, &spec.IPv4}, {document.IPv6, &spec.IPv6}} {
		if address.text == nil {
			continue
		}
		parsed, err := netip.ParseAddr(*address.text)
		if err != nil {
			return interchange.Spec{}, interchange.ErrInvalid
		}
		*address.target = parsed
	}
	for _, text := range document.NetworkIDs {
		id, err := network.ParseID(text)
		if err != nil {
			return interchange.Spec{}, interchange.ErrInvalid
		}
		spec.Networks = append(spec.Networks, id)
	}
	spec.Networks = interchange.SortNetworks(spec.Networks)
	return spec, nil
}

func privateInterchangeDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return interchange.ErrForbidden
		case "P0002":
			return interchange.ErrNotFound
		case "40001":
			return interchange.ErrVersionConflict
		case "MTP01":
			return interchange.ErrUnknownNetwork
		case "MTP02", "MTP04":
			return interchange.ErrLimit
		case "MTP03", "23505":
			return interchange.ErrConflict
		case "22023", "22P02", "23514":
			return interchange.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return interchange.ErrForbidden
	}
	return errors.Join(interchange.ErrUnavailable, err)
}

func (store *PrivateInterchangeStore) begin(ctx context.Context) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, interchange.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(interchange.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(interchange.ErrUnavailable, err)
	}
	return tx, nil
}

// List authorizes interchange.read and returns the active relays with
// whether the Session may manage them.
func (store *PrivateInterchangeStore) List(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (_ interchange.Listing, resultErr error) {
	if !session.IsValid() || !workspaceID.IsValid() {
		return interchange.Listing{}, interchange.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return interchange.Listing{}, err
	}
	var encoded *string
	if err := tx.QueryRow(ctx, listWorkspacePrivateInterchangesSQL,
		append(sessionQueryArguments(session), workspaceID.String())...).Scan(&encoded); err != nil {
		return interchange.Listing{}, privateInterchangeDatabaseError(err)
	}
	if encoded == nil {
		return interchange.Listing{}, interchange.ErrForbidden
	}
	var envelope struct {
		Interchanges []privateInterchangeDocument `json:"interchanges"`
		CanManage    bool                         `json:"can_manage"`
	}
	if err := decodeIdentityCatalogJSON([]byte(*encoded), &envelope); err != nil || envelope.Interchanges == nil {
		return interchange.Listing{}, interchange.ErrInvalid
	}
	listing := interchange.Listing{Interchanges: make([]interchange.Interchange, 0, len(envelope.Interchanges)),
		CanManage: envelope.CanManage}
	for _, document := range envelope.Interchanges {
		item, err := document.interchange()
		if err != nil {
			return interchange.Listing{}, err
		}
		listing.Interchanges = append(listing.Interchanges, item)
	}
	return listing, nil
}

// Change commits one relay change, its Workspace evidence and the wake
// events of the Networks it advanced, in one transaction.
func (store *PrivateInterchangeStore) Change(ctx context.Context,
	change interchange.Change) (_ interchange.Result, resultErr error) {
	if !change.Session.IsValid() || !change.WorkspaceID.IsValid() || !change.InterchangeID.IsValid() ||
		!change.CorrelationID.IsValid() ||
		(change.Operation != interchange.OperationDelete && !change.Spec.IsValid()) {
		return interchange.Result{}, interchange.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return interchange.Result{}, interchange.ErrUnavailable
	}
	var expected *int64
	if change.Operation != interchange.OperationCreate {
		version := change.ExpectedVersion
		expected = &version
	}
	args := append(sessionQueryArguments(change.Session), change.WorkspaceID.String(), string(change.Operation),
		change.InterchangeID.String(), expected)
	if change.Operation == interchange.OperationDelete {
		args = append(args, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	} else {
		spec := change.Spec
		networks := make([]string, len(spec.Networks))
		for index, id := range spec.Networks {
			networks[index] = id.String()
		}
		args = append(args, spec.Name, spec.RegionCode, spec.HostName, optionalAddress(spec.IPv4),
			optionalAddress(spec.IPv6), spec.RelayKey[:], int(spec.UDPPort), int(spec.TLSPort), int(spec.STUNPort),
			networks)
	}
	args = append(args, changeID.String())
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return interchange.Result{}, err
	}
	var encoded, previousEncoded, advancedEncoded string
	var actor catalogAuthority
	if err := tx.QueryRow(ctx, changeWorkspacePrivateInterchangeSQL, args...).Scan(&encoded, &previousEncoded,
		&advancedEncoded, &actor.BindingID, &actor.RoleID, &actor.BindingGeneration, &actor.MembershipGeneration,
		&actor.OwnerGeneration); err != nil {
		return interchange.Result{}, privateInterchangeDatabaseError(err)
	}
	var document privateInterchangeDocument
	if err := decodeIdentityCatalogJSON([]byte(encoded), &document); err != nil {
		return interchange.Result{}, interchange.ErrInvalid
	}
	saved, err := document.interchange()
	if err != nil || saved.ID != change.InterchangeID {
		return interchange.Result{}, interchange.ErrInvalid
	}
	deleted := document.State == "deleted"
	if deleted != (change.Operation == interchange.OperationDelete) ||
		(change.Operation == interchange.OperationCreate) != (saved.Version == 1) ||
		(change.Operation != interchange.OperationCreate && saved.Version != change.ExpectedVersion+1) {
		return interchange.Result{}, interchange.ErrInvalid
	}
	var advancedWire []struct {
		NetworkID       string `json:"network_id"`
		NetworkRevision int64  `json:"network_revision"`
		GroupRevision   int64  `json:"group_revision"`
	}
	if err := decodeIdentityCatalogJSON([]byte(advancedEncoded), &advancedWire); err != nil {
		return interchange.Result{}, interchange.ErrInvalid
	}
	advanced := make([]identitygroup.AdvancedNetwork, 0, len(advancedWire))
	result := interchange.Result{Interchange: saved, Deleted: deleted}
	for _, entry := range advancedWire {
		id, err := network.ParseID(entry.NetworkID)
		if err != nil || entry.NetworkRevision <= 0 {
			return interchange.Result{}, interchange.ErrInvalid
		}
		advanced = append(advanced, identitygroup.AdvancedNetwork{NetworkID: id,
			NetworkRevision: entry.NetworkRevision, GroupRevision: entry.GroupRevision})
		result.Advanced = append(result.Advanced, interchange.AdvancedNetwork{NetworkID: id,
			NetworkRevision: entry.NetworkRevision})
	}
	if err := appendPrivateInterchangeEvidence(ctx, tx, change, saved, previousEncoded, actor, changeID,
		advanced); err != nil {
		return interchange.Result{}, errors.Join(interchange.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return interchange.Result{}, errors.Join(interchange.ErrUnavailable, err)
	}
	return result, nil
}

func optionalAddress(addr netip.Addr) any {
	if !addr.IsValid() {
		return nil
	}
	return addr.String()
}

// privateInterchangeSemanticHash binds the evidence to the relay as the API
// shows it.
func privateInterchangeSemanticHash(encoded string) [32]byte {
	return sha256.Sum256([]byte(encoded))
}

func appendPrivateInterchangeEvidence(ctx context.Context, tx accountSessionTransaction, change interchange.Change,
	saved interchange.Interchange, previousEncoded string, actor catalogAuthority, changeID publicid.ID,
	advanced []identitygroup.AdvancedNetwork) error {
	action := "interchange." + map[interchange.Operation]string{
		interchange.OperationCreate: "created", interchange.OperationUpdate: "updated",
		interchange.OperationDelete: "deleted",
	}[change.Operation]
	current, err := json.Marshal(privateInterchangeEvidence(saved))
	if err != nil {
		return err
	}
	after := privateInterchangeSemanticHash(string(current))
	var before *[32]byte
	if previousEncoded != "" {
		var previous privateInterchangeDocument
		if err := decodeIdentityCatalogJSON([]byte(previousEncoded), &previous); err != nil {
			return err
		}
		item, err := previous.interchange()
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(privateInterchangeEvidence(item))
		if err != nil {
			return err
		}
		hash := privateInterchangeSemanticHash(string(encoded))
		before = &hash
	}
	base := catalogEvent{
		session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
		aggregateKind: "private_interchange", aggregateID: saved.ID, version: saved.Version,
		action: action, permission: "interchange.manage", before: before, after: after,
		payload: struct {
			WorkspaceID string                        `json:"workspace_id"`
			SessionID   string                        `json:"session_id"`
			Interchange privateInterchangeEvidenceDoc `json:"interchange"`
			Authority   catalogAuthority              `json:"authority"`
		}{change.WorkspaceID.String(), change.Session.ID().String(), privateInterchangeEvidence(saved), actor},
		outboxClass: action,
		outbox: struct {
			WorkspaceID   string `json:"workspace_id"`
			InterchangeID string `json:"interchange_id"`
			Version       int64  `json:"version"`
		}{change.WorkspaceID.String(), saved.ID.String(), saved.Version},
	}
	if err := appendWorkspaceCatalogEvent(ctx, tx, change.WorkspaceID, base); err != nil {
		return err
	}
	return appendNetworkWakeEvents(ctx, tx, advanced, base, struct {
		Kind          string `json:"kind"`
		InterchangeID string `json:"interchange_id"`
	}{"private_interchange_changed", saved.ID.String()})
}

// privateInterchangeEvidenceDoc is what the evidence records about a relay:
// everything an auditor needs to see what was granted, in a stable form.
type privateInterchangeEvidenceDoc struct {
	ID         string   `json:"interchange_id"`
	Name       string   `json:"name"`
	RegionID   uint16   `json:"region_id"`
	RegionCode string   `json:"region_code"`
	HostName   string   `json:"host_name"`
	IPv4       string   `json:"ipv4,omitempty"`
	IPv6       string   `json:"ipv6,omitempty"`
	RelayKey   string   `json:"relay_key"`
	UDPPort    uint16   `json:"udp_port"`
	TLSPort    uint16   `json:"tls_port"`
	STUNPort   uint16   `json:"stun_port"`
	NetworkIDs []string `json:"network_ids"`
}

func privateInterchangeEvidence(item interchange.Interchange) privateInterchangeEvidenceDoc {
	doc := privateInterchangeEvidenceDoc{ID: item.ID.String(), Name: item.Spec.Name, RegionID: item.RegionID,
		RegionCode: item.Spec.RegionCode, HostName: item.Spec.HostName, RelayKey: item.Spec.RelayKey.String(),
		UDPPort: item.Spec.UDPPort, TLSPort: item.Spec.TLSPort, STUNPort: item.Spec.STUNPort,
		NetworkIDs: make([]string, len(item.Spec.Networks))}
	if item.Spec.IPv4.IsValid() {
		doc.IPv4 = item.Spec.IPv4.String()
	}
	if item.Spec.IPv6.IsValid() {
		doc.IPv6 = item.Spec.IPv6.String()
	}
	for index, id := range item.Spec.Networks {
		doc.NetworkIDs[index] = id.String()
	}
	return doc
}

// PrivateInterchangeDirectoryStore reads every active relay of the
// deployment for the control plane, with the runtime pool and no session.
type PrivateInterchangeDirectoryStore struct {
	database resourceAuthorityDatabase
}

// ErrPrivateInterchangeDirectory classifies an unavailable or malformed read.
var ErrPrivateInterchangeDirectory = errors.New("postgres: private interchange directory unavailable")

// NewPrivateInterchangeDirectoryStore accepts only the runtime pool.
func NewPrivateInterchangeDirectoryStore(pool *Pool) (*PrivateInterchangeDirectoryStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil {
		return nil, ErrPrivateInterchangeDirectory
	}
	return &PrivateInterchangeDirectoryStore{database: pool.resourceAuthorityDatabase}, nil
}

// ReadPrivateInterchanges returns the active relays and the revision.
func (store *PrivateInterchangeDirectoryStore) ReadPrivateInterchanges(ctx context.Context) (interchange.Directory, error) {
	if store == nil || store.database == nil || ctx == nil {
		return interchange.Directory{}, ErrPrivateInterchangeDirectory
	}
	transaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return interchange.Directory{}, errors.Join(ErrPrivateInterchangeDirectory, err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	var encoded string
	if err := transaction.QueryRow(ctx, privateInterchangeDirectorySQL).Scan(&encoded); err != nil {
		return interchange.Directory{}, errors.Join(ErrPrivateInterchangeDirectory, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return interchange.Directory{}, errors.Join(ErrPrivateInterchangeDirectory, err)
	}
	return decodePrivateInterchangeDirectory(encoded)
}

func decodePrivateInterchangeDirectory(encoded string) (interchange.Directory, error) {
	var wire struct {
		Revision     int64                        `json:"revision"`
		Interchanges []privateInterchangeDocument `json:"interchanges"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &wire); err != nil || wire.Revision < 0 ||
		wire.Interchanges == nil {
		return interchange.Directory{}, ErrPrivateInterchangeDirectory
	}
	directory := interchange.Directory{Revision: wire.Revision}
	for _, document := range wire.Interchanges {
		id, err := publicid.Parse(document.ID)
		if err != nil || document.RegionID < 1000 || document.RegionID > 64999 {
			return interchange.Directory{}, ErrPrivateInterchangeDirectory
		}
		spec, err := document.spec()
		if err != nil || !spec.IsValid() {
			return interchange.Directory{}, ErrPrivateInterchangeDirectory
		}
		directory.Relays = append(directory.Relays, interchange.Interchange{ID: id,
			RegionID: uint16(document.RegionID), Spec: spec})
	}
	return directory, nil
}
