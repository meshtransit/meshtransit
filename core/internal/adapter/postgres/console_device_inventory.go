package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// readConsoleDeviceInventorySQL reads a page in name order with each
// Device's DNS label, the first 16 prefixes it offers and the scope's display
// codes (schema 192).
const readConsoleDeviceInventorySQL = `SELECT mesh_ops.read_console_devices_v5(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::TEXT, $14::TEXT, $15::TEXT, $16::UUID, $17::INTEGER
)::TEXT`

// readConsoleDeviceSQL reads one Device with every prefix it offers, how it
// was enrolled and the mesh addresses it holds (schema 209).
const readConsoleDeviceSQL = `SELECT mesh_ops.read_console_device_v3(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::UUID
)::TEXT`

// readConsoleDeviceNamesSQL names up to 100 Devices of the scope (schema 177).
const readConsoleDeviceNamesSQL = `SELECT mesh_ops.read_console_device_names_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::UUID[]
)::TEXT`

// ConsoleDeviceInventoryStore owns bounded reads with authorization row locks.
type ConsoleDeviceInventoryStore struct {
	database resourceAuthorityDatabase
	options  AccountSessionOptions
	metrics  *postgresPoolMetrics
}

// NewConsoleDeviceInventoryStore binds the account-session runtime pool.
func NewConsoleDeviceInventoryStore(pool *Pool, options AccountSessionOptions) (*ConsoleDeviceInventoryStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil || !validAccountSessionOptions(options) {
		return nil, inventory.ErrUnavailable
	}
	return &ConsoleDeviceInventoryStore{database: pool.resourceAuthorityDatabase, options: options, metrics: pool.metrics}, nil
}

// ReadDevices loads a bounded exact-scope page in name order after current
// device.read checks on the database clock, rerun on a fresh snapshot when a
// concurrent change holds the revision row.
func (store *ConsoleDeviceInventoryStore) ReadDevices(ctx context.Context, session accountsession.Session,
	scope network.Scope, query inventory.Query,
) (inventory.ReadResult, error) {
	// The service asks one Device past its page, so up to MaximumPageSize+1.
	if query.Limit < 1 || query.Limit > inventory.MaximumPageSize+1 || !withLimit(query, 1).IsValid() {
		return inventory.ReadResult{}, inventory.ErrInvalidRequest
	}
	encoded, err := retryReadConflict(ctx, func() (*string, error) {
		return store.readOnce(ctx, session, scope, func(transaction resourceAuthorityDatabaseTransaction,
			evaluatedAt time.Time) (*string, error) {
			var encoded *string
			err := transaction.QueryRow(ctx, readConsoleDeviceInventorySQL,
				append(consoleDeviceReadArguments(session, scope, evaluatedAt), nullableText(query.NamePrefix),
					nullableText(string(query.State)), nullableText(query.Cursor.AfterHostname),
					nullableNodeID(query.Cursor.After), query.Limit)...,
			).Scan(&encoded)
			return encoded, err
		})
	})
	if err != nil {
		return inventory.ReadResult{}, err
	}
	return decodeConsoleDeviceInventory(*encoded)
}

// ReadDevice loads one Device of the scope and how it was enrolled.
func (store *ConsoleDeviceInventoryStore) ReadDevice(ctx context.Context, session accountsession.Session,
	scope network.Scope, id node.ID,
) (inventory.Record, error) {
	if !id.IsValid() {
		return inventory.Record{}, inventory.ErrInvalidRequest
	}
	encoded, err := retryReadConflict(ctx, func() (*string, error) {
		return store.readOnce(ctx, session, scope, func(transaction resourceAuthorityDatabaseTransaction,
			evaluatedAt time.Time) (*string, error) {
			var encoded *string
			err := transaction.QueryRow(ctx, readConsoleDeviceSQL,
				append(consoleDeviceReadArguments(session, scope, evaluatedAt), id.String())...,
			).Scan(&encoded)
			return encoded, err
		})
	})
	if err != nil {
		return inventory.Record{}, err
	}
	return decodeConsoleDevice(*encoded)
}

// ReadDeviceNames names the scope's Devices among ids.
func (store *ConsoleDeviceInventoryStore) ReadDeviceNames(ctx context.Context, session accountsession.Session,
	scope network.Scope, ids []node.ID,
) (map[node.ID]string, error) {
	if len(ids) > inventory.MaximumNames {
		return nil, inventory.ErrInvalidRequest
	}
	texts := make([]string, len(ids))
	for index, id := range ids {
		if !id.IsValid() {
			return nil, inventory.ErrInvalidRequest
		}
		texts[index] = id.String()
	}
	encoded, err := retryReadConflict(ctx, func() (*string, error) {
		return store.readOnce(ctx, session, scope, func(transaction resourceAuthorityDatabaseTransaction,
			evaluatedAt time.Time) (*string, error) {
			var encoded *string
			err := transaction.QueryRow(ctx, readConsoleDeviceNamesSQL,
				append(consoleDeviceReadArguments(session, scope, evaluatedAt), texts)...,
			).Scan(&encoded)
			return encoded, err
		})
	})
	if err != nil {
		return nil, err
	}
	var wire struct {
		WorkspaceID string `json:"workspace_id"`
		NetworkID   string `json:"network_id"`
		Names       []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		} `json:"names"`
	}
	if !decodeConsoleJSON(*encoded, &wire) || wire.Names == nil || len(wire.Names) > len(ids) ||
		wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() {
		return nil, inventory.ErrInvalidResult
	}
	names := make(map[node.ID]string, len(wire.Names))
	for _, entry := range wire.Names {
		id, idErr := node.ParseID(entry.ID)
		hostname, hostnameErr := node.ParseHostname(entry.Hostname)
		if idErr != nil || hostnameErr != nil {
			return nil, inventory.ErrInvalidResult
		}
		names[id] = hostname.String()
	}
	return names, nil
}

// withLimit returns query with another page size.
func withLimit(query inventory.Query, limit int) inventory.Query {
	query.Limit = limit
	return query
}

func consoleDeviceReadArguments(session accountsession.Session, scope network.Scope, evaluatedAt time.Time) []any {
	return []any{
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt,
	}
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableNodeID(id node.ID) any {
	if !id.IsValid() {
		return nil
	}
	return id.String()
}

// readOnce runs one authorized read in a repeatable-read transaction on the
// database clock; a NULL answer means the session lacks device.read.
func (store *ConsoleDeviceInventoryStore) readOnce(ctx context.Context, session accountsession.Session,
	scope network.Scope, read func(resourceAuthorityDatabaseTransaction, time.Time) (*string, error),
) (_ *string, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.metrics != nil {
			store.metrics.observeOperation(postgresOperationConsoleDeviceInventory, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !scope.IsValid() {
		return nil, inventory.ErrInvalidRequest
	}
	// RBAC and revision FOR SHARE locks require a read-write transaction; the
	// invoked function has no mutation statements or new write privileges.
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil || transaction == nil {
		return nil, errors.Join(inventory.ErrUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureAccountSessionReadTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return nil, errors.Join(inventory.ErrUnavailable, err)
	}
	if err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('lock_timeout', $1, TRUE)`,
		postgresTimeout(store.options.StatementTimeout),
	); err != nil {
		return nil, errors.Join(inventory.ErrUnavailable, err)
	}
	evaluatedAt, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return nil, errors.Join(inventory.ErrUnavailable, err)
	}
	encoded, err := read(transaction, evaluatedAt)
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "22023" {
		// The function refused the input, a cursor naming no Device for one.
		return nil, inventory.ErrInvalidRequest
	}
	if err != nil {
		return nil, errors.Join(inventory.ErrUnavailable, err)
	}
	if encoded == nil {
		return nil, inventory.ErrForbidden
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, errors.Join(inventory.ErrUnavailable, err)
	}
	closed = true
	return encoded, nil
}

type consoleDeviceInventoryWire struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	Revision    int64  `json:"inventory_revision"`
	// Schema 169: the scope's display codes.
	WorkspaceCode string                        `json:"workspace_code"`
	NetworkCode   string                        `json:"network_code"`
	Devices       []consoleDeviceInventoryEntry `json:"devices"`
}

type consoleDeviceInventoryEntry struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	State     string    `json:"state"`
	Ephemeral *bool     `json:"is_ephemeral"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Schema 125 lifecycle.
	Ownership       string                        `json:"ownership"`
	Owner           *consoleDeviceInventoryMember `json:"owner"`
	SuspendedReason *string                       `json:"suspended_reason"`
	HandoverTo      *consoleDeviceInventoryMember `json:"handover_to"`
	// Schema 169: null for a Device that holds no label (revoked).
	DNSLabel *string `json:"dns_label"`
	// Schema 192: the first prefixes the Device offers to forward and how
	// many it offers.
	AdvertisedPrefixes    []string `json:"advertised_prefixes"`
	AdvertisedPrefixCount *int     `json:"advertised_prefix_count"`
}

type consoleDeviceInventoryMember struct {
	PrincipalID string `json:"principal_id"`
	DisplayName string `json:"display_name"`
}

func (member *consoleDeviceInventoryMember) parse() (inventory.Member, bool) {
	if member == nil {
		return inventory.Member{}, true
	}
	id, err := publicid.Parse(member.PrincipalID)
	return inventory.Member{PrincipalID: id, DisplayName: member.DisplayName}, err == nil && len(member.DisplayName) <= 255
}

// decodeConsoleJSON reads exactly one bounded JSON value, refusing unknown
// fields.
func decodeConsoleJSON(encoded string, value any) bool {
	if len(encoded) > 1024*1024 {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return false
	}
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func decodeConsoleScope(workspaceText, networkText, workspaceCodeText, networkCodeText string) (
	network.Scope, identity.DisplayCode, identity.DisplayCode, bool,
) {
	workspaceID, workspaceErr := workspace.ParseID(workspaceText)
	networkID, networkErr := network.ParseID(networkText)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	workspaceCode, workspaceCodeErr := identity.ParseDisplayCode(workspaceCodeText)
	networkCode, networkCodeErr := identity.ParseDisplayCode(networkCodeText)
	return scope, workspaceCode, networkCode, workspaceErr == nil && networkErr == nil && scopeErr == nil &&
		workspaceCodeErr == nil && networkCodeErr == nil
}

func decodeConsoleDeviceInventory(encoded string) (inventory.ReadResult, error) {
	var wire consoleDeviceInventoryWire
	if !decodeConsoleJSON(encoded, &wire) || wire.Devices == nil || len(wire.Devices) > inventory.MaximumPageSize+1 {
		return inventory.ReadResult{}, inventory.ErrInvalidResult
	}
	scope, workspaceCode, networkCode, ok := decodeConsoleScope(wire.WorkspaceID, wire.NetworkID,
		wire.WorkspaceCode, wire.NetworkCode)
	if !ok || wire.Revision < 1 {
		return inventory.ReadResult{}, inventory.ErrInvalidResult
	}
	result := inventory.ReadResult{Scope: scope, Revision: wire.Revision, Devices: make([]inventory.Device, len(wire.Devices)),
		WorkspaceCode: workspaceCode, NetworkCode: networkCode}
	for index, item := range wire.Devices {
		device, ok := item.parse()
		if !ok {
			return inventory.ReadResult{}, inventory.ErrInvalidResult
		}
		result.Devices[index] = device
	}
	return result, nil
}

func (item consoleDeviceInventoryEntry) parse() (inventory.Device, bool) {
	if item.Ephemeral == nil {
		return inventory.Device{}, false
	}
	id, idErr := node.ParseID(item.ID)
	hostname, hostnameErr := node.ParseHostname(item.Hostname)
	device, deviceErr := inventory.NewDevice(id, hostname, item.State, *item.Ephemeral,
		item.Version, item.CreatedAt, item.UpdatedAt, item.ExpiresAt)
	owner, ownerOK := item.Owner.parse()
	handover, handoverOK := item.HandoverTo.parse()
	if idErr != nil || hostnameErr != nil || deviceErr != nil || !ownerOK || !handoverOK {
		return inventory.Device{}, false
	}
	lifecycle := inventory.Lifecycle{Ownership: item.Ownership, Owner: owner, HandoverTo: handover}
	if item.SuspendedReason != nil {
		lifecycle.SuspendedReason = *item.SuspendedReason
	}
	if device, deviceErr = device.WithLifecycle(lifecycle); deviceErr != nil {
		return inventory.Device{}, false
	}
	if item.AdvertisedPrefixes == nil || item.AdvertisedPrefixCount == nil {
		return inventory.Device{}, false
	}
	offer := make([]netip.Prefix, len(item.AdvertisedPrefixes))
	for index, text := range item.AdvertisedPrefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return inventory.Device{}, false
		}
		offer[index] = prefix
	}
	if device, deviceErr = device.WithOffer(offer, *item.AdvertisedPrefixCount); deviceErr != nil {
		return inventory.Device{}, false
	}
	if item.DNSLabel != nil {
		label, labelErr := node.ParseDNSLabel(*item.DNSLabel)
		if labelErr != nil {
			return inventory.Device{}, false
		}
		if device, deviceErr = device.WithDNSLabel(label); deviceErr != nil {
			return inventory.Device{}, false
		}
	}
	return device, true
}

type consoleDeviceWire struct {
	WorkspaceID   string                       `json:"workspace_id"`
	NetworkID     string                       `json:"network_id"`
	WorkspaceCode string                       `json:"workspace_code"`
	NetworkCode   string                       `json:"network_code"`
	Device        *consoleDeviceInventoryEntry `json:"device"`
	Enrollment    *struct {
		Kind        string                        `json:"kind"`
		KeyID       string                        `json:"key_id"`
		Description string                        `json:"description"`
		CreatedBy   *consoleDeviceInventoryMember `json:"created_by"`
	} `json:"enrollment"`
	Tags []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"tags"`
	Addresses []string `json:"addresses"`
}

// maximumDeviceAddresses bounds the addresses one Device holds: one primary
// lease per family, with room for a lease being replaced.
const maximumDeviceAddresses = 4

// decodeDeviceAddresses reads canonical single addresses, IPv4 before IPv6.
func decodeDeviceAddresses(encoded []string) ([]netip.Addr, bool) {
	if len(encoded) > maximumDeviceAddresses {
		return nil, false
	}
	addresses := make([]netip.Addr, len(encoded))
	for index, text := range encoded {
		address, err := netip.ParseAddr(text)
		if err != nil || address.String() != text || address.Zone() != "" ||
			(index > 0 && address.Is4() && addresses[index-1].Is6()) {
			return nil, false
		}
		addresses[index] = address
	}
	return addresses, true
}

func decodeConsoleDevice(encoded string) (inventory.Record, error) {
	var wire consoleDeviceWire
	if !decodeConsoleJSON(encoded, &wire) {
		return inventory.Record{}, inventory.ErrInvalidResult
	}
	scope, workspaceCode, networkCode, ok := decodeConsoleScope(wire.WorkspaceID, wire.NetworkID,
		wire.WorkspaceCode, wire.NetworkCode)
	if !ok || (wire.Device == nil) != (wire.Enrollment == nil) || (wire.Device == nil) != (wire.Tags == nil) ||
		(wire.Device == nil) != (wire.Addresses == nil) {
		return inventory.Record{}, inventory.ErrInvalidResult
	}
	record := inventory.Record{Scope: scope, WorkspaceCode: workspaceCode, NetworkCode: networkCode}
	if wire.Device == nil {
		return record, nil
	}
	device, ok := wire.Device.parse()
	if !ok {
		return inventory.Record{}, inventory.ErrInvalidResult
	}
	record.Device, record.Found = device, true
	if record.Addresses, ok = decodeDeviceAddresses(wire.Addresses); !ok {
		return inventory.Record{}, inventory.ErrInvalidResult
	}
	record.Tags = make([]inventory.Tag, len(wire.Tags))
	for index, tag := range wire.Tags {
		id, err := publicid.Parse(tag.ID)
		if err != nil || tag.Name == "" || len(tag.Name) > devicetag.MaximumNameLength {
			return inventory.Record{}, inventory.ErrInvalidResult
		}
		record.Tags[index] = inventory.Tag{ID: id, Name: tag.Name}
	}
	switch wire.Enrollment.Kind {
	case "browser":
		if wire.Enrollment.KeyID != "" || wire.Enrollment.CreatedBy != nil {
			return inventory.Record{}, inventory.ErrInvalidResult
		}
	case "key":
		keyID, err := publicid.Parse(wire.Enrollment.KeyID)
		creator, creatorOK := wire.Enrollment.CreatedBy.parse()
		if err != nil || wire.Enrollment.CreatedBy == nil || !creatorOK || len(wire.Enrollment.Description) > 128 {
			return inventory.Record{}, inventory.ErrInvalidResult
		}
		record.Enrollment = inventory.Enrollment{ByKey: true, KeyID: keyID,
			KeyDescription: wire.Enrollment.Description, KeyCreatedBy: creator}
	default:
		return inventory.Record{}, inventory.ErrInvalidResult
	}
	return record, nil
}
