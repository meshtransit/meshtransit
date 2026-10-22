package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const maximumDNSZoneDocumentBytes = 1 << 20

const listDNSZonesSQL = `SELECT mesh_ops.list_dns_zones_v2(` + sessionArguments + `,$10::UUID,$11::UUID,
 NULLIF($12::TEXT,'')::UUID,$13::INTEGER)::TEXT`

const readDNSZoneSQL = `SELECT mesh_ops.read_dns_zone_v2(` + sessionArguments + `,$10::UUID,$11::UUID,$12::UUID)::TEXT`

const changeDNSZoneSQL = `SELECT mesh_ops.change_dns_zone_v2(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::UUID,$14::BIGINT,$15::TEXT,$16::TEXT,$17::TEXT,$18::JSONB,$19::UUID[],
 $20::INTEGER,$21::TEXT,$22::TEXT,$23::BOOLEAN,$24::INTEGER,$25::INTEGER,$26::INTEGER,$27::INTEGER,$28::BOOLEAN,
 $29::UUID)::TEXT`

const appendDNSZoneEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network_dns_zone',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,$12::TEXT,
 $13::UUID,$14::BYTEA,$15::BYTEA,$16::JSONB,'network.revision.advanced',$17::JSONB)`

// dnsZonePermission is the permission every zone change is made under.
const dnsZonePermission = "dns.manage"

// DNSZoneStore reads and changes the DNS zones of a Network through the
// runtime pool. Each change commits with its evidence on the Network stream
// and wakes map sessions through the revision outbox.
type DNSZoneStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ dnszone.Store = (*DNSZoneStore)(nil)

// NewDNSZoneStore uses the runtime pool.
func NewDNSZoneStore(pool *Pool, options AccountSessionOptions) (*DNSZoneStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, dnszone.ErrInvalid
	}
	return &DNSZoneStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func dnsZoneDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return dnszone.ErrForbidden
		case "P0002":
			return dnszone.ErrNotFound
		case "40001":
			return dnszone.ErrVersionConflict
		case "MTZ01":
			return dnszone.ErrDomainTaken
		case "MTZ02":
			return dnszone.ErrZoneLimit
		case "MTZ03":
			return dnszone.ErrResolverNotEligible
		case "MTZ04":
			return dnszone.ErrGroupNotFound
		case "MTZ05":
			return dnszone.ErrSearchLimit
		case "MTZ06":
			return dnszone.ErrResolverPeerLimit
		case "MTZ07":
			return dnszone.ErrZoneHoldsNames
		case "MTZ0E":
			return dnszone.ErrNXDomainPublic
		case "MTZ08":
			return dnszone.ErrNameTaken
		case "MTZ09":
			return dnszone.ErrNameInOtherZone
		case "MTZ0A":
			return dnszone.ErrNameLimit
		case "MTZ0B":
			return dnszone.ErrNameTargetInvalid
		case "MTZ0C":
			return dnszone.ErrCNAMEAtApex
		case "MTZ0D":
			return dnszone.ErrCNAMELoop
		case "MTZ10":
			return dnszone.ErrShareTargetInvalid
		case "22023", "22P02", "23514":
			return dnszone.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return dnszone.ErrForbidden
	}
	return errors.Join(dnszone.ErrUnavailable, err)
}

// begin starts one unit of work in the Network scope.
func (store *DNSZoneStore) begin(ctx context.Context, scope network.Scope) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, dnszone.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(dnszone.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(dnszone.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return tx, dnsZoneDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return tx, dnszone.ErrForbidden
	}
	return tx, nil
}

func decodeDNSZoneJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumDNSZoneDocumentBytes {
		return dnszone.ErrInvalid
	}
	return decodeStrictJSON(string(encoded), maximumDNSZoneDocumentBytes, target)
}

// dnsZoneResolverDocument is one resolver as stored, with what Core knows of
// a resolver Device.
type dnsZoneResolverDocument struct {
	DeviceID    string  `json:"device_id,omitempty"`
	Address     string  `json:"address,omitempty"`
	Port        int     `json:"port"`
	DeviceName  *string `json:"device_name,omitempty"`
	DeviceState string  `json:"device_state,omitempty"`
	Ownership   *string `json:"ownership,omitempty"`
	ExitNode    *bool   `json:"exit_node,omitempty"`
}

type dnsZoneGroupDocument struct {
	GroupID string `json:"group_id"`
	Name    string `json:"name"`
	State   string `json:"state"`
}

type dnsZoneDocument struct {
	ID                string                    `json:"zone_id"`
	Domain            string                    `json:"domain"`
	OtherNames        string                    `json:"other_names"`
	FailureMode       string                    `json:"failure_mode"`
	Resolvers         []dnsZoneResolverDocument `json:"resolvers"`
	Groups            []dnsZoneGroupDocument    `json:"groups"`
	SearchPosition    *int                      `json:"search_position"`
	PublicClass       string                    `json:"public_class"`
	PublicListVersion string                    `json:"public_list_version"`
	PublicConfirmed   bool                      `json:"public_confirmed"`
	NameCount         int                       `json:"name_count"`
	State             string                    `json:"state"`
	Version           int64                     `json:"version"`
	CreatedAt         time.Time                 `json:"created_at"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}

func (document dnsZoneResolverDocument) resolver() (dnszone.ZoneResolver, error) {
	if document.Port < 1 || document.Port > 65535 || (document.DeviceID == "") == (document.Address == "") {
		return dnszone.ZoneResolver{}, dnszone.ErrInvalid
	}
	if document.Address != "" {
		address, err := netip.ParseAddr(document.Address)
		if err != nil || document.DeviceName != nil || document.ExitNode != nil {
			return dnszone.ZoneResolver{}, dnszone.ErrInvalid
		}
		return dnszone.ZoneResolver{Resolver: dnszone.Resolver{Address: address,
			Port: uint16(document.Port)}}, nil
	}
	device, err := node.ParseID(document.DeviceID)
	if err != nil || document.DeviceState == "" || document.ExitNode == nil {
		return dnszone.ZoneResolver{}, dnszone.ErrInvalid
	}
	about := &dnszone.ResolverDevice{State: document.DeviceState, ExitNode: *document.ExitNode}
	if document.DeviceName != nil {
		about.Name = *document.DeviceName
	}
	if document.Ownership != nil {
		about.Ownership = *document.Ownership
	}
	return dnszone.ZoneResolver{Resolver: dnszone.Resolver{DeviceID: device,
		Port: uint16(document.Port)}, Device: about}, nil
}

var dnsZoneClasses = map[string]dnszone.Class{"private": dnszone.ClassPrivate, "public": dnszone.ClassPublic}

func (document dnsZoneDocument) zone(allowDeleted bool) (dnszone.Zone, error) {
	id, err := dnszone.ParseID(document.ID)
	class, known := dnsZoneClasses[document.PublicClass]
	mode := dnszone.FailureMode(document.FailureMode)
	other := dnszone.OtherNames(document.OtherNames)
	forward := other == dnszone.OtherForward
	if err != nil || !known || !mode.IsKnown() || !other.IsKnown() || document.Version <= 0 ||
		(len(document.Resolvers) == 0) == forward || len(document.Resolvers) > dnszone.MaximumResolversPerZone ||
		document.NameCount < 0 || document.NameCount > dnszone.MaximumNamesPerZone ||
		len(document.Groups) > dnszone.MaximumGroupsPerZone || document.PublicListVersion == "" ||
		document.CreatedAt.IsZero() || document.UpdatedAt.Before(document.CreatedAt) ||
		(document.State != "active" && (document.State != "deleted" || !allowDeleted)) {
		return dnszone.Zone{}, dnszone.ErrInvalid
	}
	zone := dnszone.Zone{
		ID: id, Domain: dnszone.Domain(document.Domain), OtherNames: other, FailureMode: mode, Class: class,
		ListVersion: document.PublicListVersion, PublicConfirmed: document.PublicConfirmed,
		NameCount: document.NameCount, Deleted: document.State == "deleted", Version: document.Version,
		CreatedAt: document.CreatedAt.UTC(), UpdatedAt: document.UpdatedAt.UTC(),
	}
	if document.SearchPosition != nil {
		position := *document.SearchPosition
		zone.SearchPosition = &position
	}
	for _, item := range document.Resolvers {
		resolver, err := item.resolver()
		if err != nil {
			return dnszone.Zone{}, err
		}
		zone.Resolvers = append(zone.Resolvers, resolver)
	}
	for _, item := range document.Groups {
		group, err := devicegroup.ParseID(item.GroupID)
		if err != nil || item.State == "" {
			return dnszone.Zone{}, dnszone.ErrInvalid
		}
		zone.Groups = append(zone.Groups, dnszone.Group{ID: group, Name: item.Name, State: item.State})
	}
	return zone, nil
}

type dnsZoneAbilitiesDocument struct {
	CanManage bool `json:"can_manage"`
}

// List returns one page of the Network's active zones (network.read).
func (store *DNSZoneStore) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	after dnszone.ID, limit int) (_ dnszone.Listing, resultErr error) {
	if !session.IsValid() || !scope.IsValid() || limit < 1 || limit > dnszone.MaximumPage {
		return dnszone.Listing{}, dnszone.ErrInvalid
	}
	afterText := ""
	if after != (dnszone.ID{}) {
		afterText = after.String()
	}
	var encoded string
	if err := store.read(ctx, scope, func(tx accountSessionTransaction) error {
		return tx.QueryRow(ctx, listDNSZonesSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), afterText, limit)...).Scan(&encoded)
	}); err != nil {
		return dnszone.Listing{}, err
	}
	var document struct {
		Zones         []dnsZoneDocument `json:"zones"`
		HasMore       bool              `json:"has_more"`
		WorkspaceCode string            `json:"workspace_code"`
		NetworkCode   string            `json:"network_code"`
		dnsZoneAbilitiesDocument
	}
	if err := decodeDNSZoneJSON([]byte(encoded), &document); err != nil || len(document.Zones) > limit {
		return dnszone.Listing{}, dnszone.ErrInvalid
	}
	workspaceCode, workspaceErr := identity.ParseDisplayCode(document.WorkspaceCode)
	networkCode, networkErr := identity.ParseDisplayCode(document.NetworkCode)
	if workspaceErr != nil || networkErr != nil {
		return dnszone.Listing{}, dnszone.ErrInvalid
	}
	listing := dnszone.Listing{Zones: make([]dnszone.Zone, 0, len(document.Zones)), HasMore: document.HasMore,
		WorkspaceCode: workspaceCode, NetworkCode: networkCode,
		Abilities: dnszone.Abilities{CanManage: document.CanManage}}
	for _, item := range document.Zones {
		zone, err := item.zone(false)
		if err != nil {
			return dnszone.Listing{}, err
		}
		listing.Zones = append(listing.Zones, zone)
	}
	return listing, nil
}

// Read returns one active zone (network.read).
func (store *DNSZoneStore) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	zoneID dnszone.ID) (dnszone.Reading, error) {
	if !session.IsValid() || !scope.IsValid() || !zoneID.IsValid() {
		return dnszone.Reading{}, dnszone.ErrInvalid
	}
	var encoded string
	if err := store.read(ctx, scope, func(tx accountSessionTransaction) error {
		return tx.QueryRow(ctx, readDNSZoneSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), zoneID.String())...).Scan(&encoded)
	}); err != nil {
		return dnszone.Reading{}, err
	}
	var document struct {
		Zone dnsZoneDocument `json:"zone"`
		dnsZoneAbilitiesDocument
	}
	if err := decodeDNSZoneJSON([]byte(encoded), &document); err != nil {
		return dnszone.Reading{}, dnszone.ErrInvalid
	}
	zone, err := document.Zone.zone(false)
	if err != nil || zone.ID != zoneID {
		return dnszone.Reading{}, dnszone.ErrInvalid
	}
	return dnszone.Reading{Zone: zone, Abilities: dnszone.Abilities{CanManage: document.CanManage}}, nil
}

// read runs one read-only query in the Network scope and rolls back.
func (store *DNSZoneStore) read(ctx context.Context, scope network.Scope,
	query func(accountSessionTransaction) error) (resultErr error) {
	tx, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return err
	}
	if err := query(tx); err != nil {
		return dnsZoneDatabaseError(err)
	}
	return nil
}

type dnsZoneChangeRecord struct {
	Zone     dnsZoneDocument  `json:"zone"`
	Previous *dnsZoneDocument `json:"previous"`
	Changed  bool             `json:"changed"`
	// Names a new zone took from shorter zones, or a deleted zone deleted.
	Names           int     `json:"names"`
	NetworkRevision int64   `json:"network_revision"`
	DNSRevision     int64   `json:"dns_revision"`
	RoleBindingID   *string `json:"role_binding_id"`
}

// dnsZoneResolversJSON encodes resolvers in the order the admin chose, the
// shape schema 213 checks.
func dnsZoneResolversJSON(resolvers []dnszone.Resolver) ([]byte, error) {
	type stored struct {
		DeviceID string `json:"device_id,omitempty"`
		Address  string `json:"address,omitempty"`
		Port     uint16 `json:"port"`
	}
	documents := make([]stored, 0, len(resolvers))
	for _, resolver := range resolvers {
		item := stored{Port: resolver.Port}
		if resolver.IsDevice() {
			item.DeviceID = resolver.DeviceID.String()
		} else {
			item.Address = resolver.Address.String()
		}
		documents = append(documents, item)
	}
	return json.Marshal(documents)
}

func dnsZoneAction(operation dnszone.Operation) string {
	switch operation {
	case dnszone.OperationCreate:
		return "dns_zone.created"
	case dnszone.OperationUpdate:
		return "dns_zone.updated"
	default:
		return "dns_zone.deleted"
	}
}

// Change authorizes dns.manage, applies the change and commits it with its
// evidence.
func (store *DNSZoneStore) Change(ctx context.Context, change dnszone.Change) (_ dnszone.Result,
	resultErr error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.ZoneID.IsValid() ||
		!change.CorrelationID.IsValid() {
		return dnszone.Result{}, dnszone.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return dnszone.Result{}, dnszone.ErrUnavailable
	}
	tx, err := store.begin(ctx, change.Scope)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return dnszone.Result{}, err
	}
	result, err := applyDNSZoneChange(ctx, tx, change, changeID)
	if err != nil {
		return dnszone.Result{}, err
	}
	if !result.Changed {
		// Nothing changed: no evidence, no wakeup; the transaction rolls back.
		return result, nil
	}
	if result.AppliesWithin, err = deferDNSChangeWakeup(ctx, tx, changeID); err != nil {
		return dnszone.Result{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return dnszone.Result{}, errors.Join(dnszone.ErrUnavailable, err)
	}
	committed = true
	return result, nil
}

// applyDNSZoneChange runs one zone change in tx, already in the change's
// Network scope, and appends its evidence when it changed something. The
// caller defers the change's wakeup and commits.
func applyDNSZoneChange(ctx context.Context, tx accountSessionTransaction, change dnszone.Change,
	changeID publicid.ID,
) (dnszone.Result, error) {
	var expected, domain, other, mode, resolvers, groups, search, class, listVersion, confirmed, zoneLimit,
		searchLimit, consumerLimit, hostLimit any
	if change.Operation != dnszone.OperationCreate {
		expected = change.ExpectedVersion
	} else {
		zoneLimit = change.Limits.ZonesPerNetwork
	}
	if change.Operation != dnszone.OperationDelete {
		encoded, err := dnsZoneResolversJSON(change.Definition.Resolvers)
		if err != nil {
			return dnszone.Result{}, dnszone.ErrInvalid
		}
		groupTexts := make([]string, 0, len(change.Definition.Groups))
		for _, group := range change.Definition.Groups {
			groupTexts = append(groupTexts, group.String())
		}
		domain, other, mode, resolvers, groups = change.Domain.String(), string(change.Definition.OtherNames),
			string(change.Definition.FailureMode), encoded, groupTexts
		if change.Definition.SearchPosition != nil {
			search = *change.Definition.SearchPosition
		}
		class, listVersion, confirmed = string(change.Class), change.ListVersion, change.Definition.PublicConfirmed
		searchLimit, consumerLimit = change.Limits.SearchZonesPerNetwork, change.Limits.ConsumersPerResolver
		hostLimit = change.Limits.HostNamesPerNetwork
	}
	var encoded string
	if err := tx.QueryRow(ctx, changeDNSZoneSQL, append(sessionQueryArguments(change.Session),
		change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), string(change.Operation),
		change.ZoneID.String(), expected, domain, other, mode, resolvers, groups, search, class, listVersion,
		confirmed, zoneLimit, searchLimit, consumerLimit, hostLimit, change.WithNames,
		changeID.String())...).Scan(&encoded); err != nil {
		return dnszone.Result{}, dnsZoneDatabaseError(err)
	}
	var record dnsZoneChangeRecord
	if err := decodeDNSZoneJSON([]byte(encoded), &record); err != nil ||
		(record.Changed && (record.NetworkRevision <= 0 || record.DNSRevision <= 0)) ||
		record.Names < 0 || (record.Names > 0 && !change.WithNames) {
		return dnszone.Result{}, dnszone.ErrInvalid
	}
	deleted := change.Operation == dnszone.OperationDelete
	saved, err := record.Zone.zone(deleted)
	if err != nil || saved.ID != change.ZoneID || saved.Deleted != deleted ||
		(record.Previous == nil) != (change.Operation == dnszone.OperationCreate) {
		return dnszone.Result{}, dnszone.ErrInvalid
	}
	result := dnszone.Result{Zone: saved, Changed: record.Changed, Names: record.Names}
	if record.Previous != nil {
		previous, err := record.Previous.zone(false)
		if err != nil || previous.Version != change.ExpectedVersion {
			return dnszone.Result{}, dnszone.ErrInvalid
		}
		result.Previous = &previous
	}
	if !record.Changed {
		return result, nil
	}
	if err := appendDNSZoneEvidence(ctx, tx, change, changeID, record); err != nil {
		return dnszone.Result{}, errors.Join(dnszone.ErrUnavailable, err)
	}
	return result, nil
}

const deferDNSChangeWakeupSQL = `SELECT mesh_ops.defer_dns_change_wakeup_v1($1::UUID)`

// deferDNSChangeWakeup holds the change's map wakeups until the Network's
// DNS window ends (schema 216) and returns how long that is.
func deferDNSChangeWakeup(ctx context.Context, tx accountSessionTransaction, changeID publicid.ID) (time.Duration,
	error) {
	var seconds int
	if err := tx.QueryRow(ctx, deferDNSChangeWakeupSQL, changeID.String()).Scan(&seconds); err != nil {
		return 0, errors.Join(dnszone.ErrUnavailable, err)
	}
	if seconds < 1 || seconds > 30 {
		return 0, dnszone.ErrUnavailable
	}
	return time.Duration(seconds) * time.Second, nil
}

// dnsZoneResolverKeys are the resolvers of a zone as they decide its
// answers: a Device and port, or an address and port, in order.
func dnsZoneResolverKeys(document dnsZoneDocument) []dnsZoneResolverDocument {
	keys := make([]dnsZoneResolverDocument, 0, len(document.Resolvers))
	for _, item := range document.Resolvers {
		keys = append(keys, dnsZoneResolverDocument{DeviceID: item.DeviceID, Address: item.Address, Port: item.Port})
	}
	return keys
}

func dnsZoneGroupIDs(document dnsZoneDocument) []string {
	ids := make([]string, 0, len(document.Groups))
	for _, item := range document.Groups {
		ids = append(ids, item.GroupID)
	}
	slices.Sort(ids)
	return ids
}

// dnsZoneSemanticHash commits to what a zone decides: its identity, domain,
// state, failure mode, resolvers, Device Groups, search position and public
// confirmation.
func dnsZoneSemanticHash(document dnsZoneDocument) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		ZoneID          string                    `json:"zone_id"`
		Domain          string                    `json:"domain"`
		State           string                    `json:"state"`
		OtherNames      string                    `json:"other_names"`
		FailureMode     string                    `json:"failure_mode"`
		Resolvers       []dnsZoneResolverDocument `json:"resolvers"`
		Groups          []string                  `json:"groups"`
		SearchPosition  *int                      `json:"search_position"`
		PublicClass     string                    `json:"public_class"`
		PublicConfirmed bool                      `json:"public_confirmed"`
	}{document.ID, document.Domain, document.State, document.OtherNames, document.FailureMode,
		dnsZoneResolverKeys(document), dnsZoneGroupIDs(document), document.SearchPosition, document.PublicClass,
		document.PublicConfirmed})
	return sha256.Sum256(encoded), err
}

// dnsZoneAuditResolver is a resolver as audit records it: a Device by ID, or
// an address, and the port.
type dnsZoneAuditResolver struct {
	DeviceID string `json:"device_id,omitempty"`
	Address  string `json:"address,omitempty"`
	Port     int    `json:"port"`
}

type dnsZoneAuditPayload struct {
	NetworkID               string                 `json:"network_id"`
	SessionID               string                 `json:"session_id"`
	RoleBindingID           string                 `json:"role_binding_id,omitempty"`
	ZoneID                  string                 `json:"dns_zone_id"`
	Domain                  string                 `json:"domain"`
	OtherNames              string                 `json:"other_names"`
	PreviousOtherNames      string                 `json:"previous_other_names,omitempty"`
	FailureMode             string                 `json:"failure_mode"`
	PreviousFailureMode     string                 `json:"previous_failure_mode,omitempty"`
	Resolvers               []dnsZoneAuditResolver `json:"resolvers"`
	PreviousResolvers       []dnsZoneAuditResolver `json:"previous_resolvers,omitempty"`
	Groups                  []string               `json:"device_groups"`
	PreviousGroups          []string               `json:"previous_device_groups,omitempty"`
	SearchPosition          *int                   `json:"search_position,omitempty"`
	PreviousSearchPosition  *int                   `json:"previous_search_position,omitempty"`
	PublicClass             string                 `json:"public_class"`
	PublicConfirmed         bool                   `json:"public_confirmed"`
	PreviousPublicConfirmed *bool                  `json:"previous_public_confirmed,omitempty"`
	// Names a new zone took from shorter zones, or a deleted zone deleted
	// with it: each name's row change carries this change's ID.
	Names int `json:"names,omitempty"`
}

func dnsZoneAuditResolvers(document dnsZoneDocument) []dnsZoneAuditResolver {
	resolvers := make([]dnsZoneAuditResolver, 0, len(document.Resolvers))
	for _, item := range document.Resolvers {
		resolvers = append(resolvers, dnsZoneAuditResolver{DeviceID: item.DeviceID, Address: item.Address,
			Port: item.Port})
	}
	return resolvers
}

func dnsZoneAudit(session accountsession.Session, networkID string, record dnsZoneChangeRecord) dnsZoneAuditPayload {
	binding := ""
	if record.RoleBindingID != nil {
		binding = *record.RoleBindingID
	}
	zone := record.Zone
	audited := dnsZoneAuditPayload{
		NetworkID: networkID, SessionID: session.ID().String(), RoleBindingID: binding, ZoneID: zone.ID,
		Domain: zone.Domain, OtherNames: zone.OtherNames, FailureMode: zone.FailureMode,
		Resolvers: dnsZoneAuditResolvers(zone), Names: record.Names,
		Groups: dnsZoneGroupIDs(zone), SearchPosition: zone.SearchPosition, PublicClass: zone.PublicClass,
		PublicConfirmed: zone.PublicConfirmed,
	}
	if previous := record.Previous; previous != nil {
		if previous.OtherNames != zone.OtherNames {
			audited.PreviousOtherNames = previous.OtherNames
		}
		if previous.FailureMode != zone.FailureMode {
			audited.PreviousFailureMode = previous.FailureMode
		}
		if !slices.Equal(dnsZoneAuditResolvers(*previous), audited.Resolvers) {
			audited.PreviousResolvers = dnsZoneAuditResolvers(*previous)
		}
		if !slices.Equal(dnsZoneGroupIDs(*previous), audited.Groups) {
			audited.PreviousGroups = dnsZoneGroupIDs(*previous)
		}
		if (previous.SearchPosition == nil) != (zone.SearchPosition == nil) ||
			(previous.SearchPosition != nil && *previous.SearchPosition != *zone.SearchPosition) {
			audited.PreviousSearchPosition = previous.SearchPosition
		}
		if previous.PublicConfirmed != zone.PublicConfirmed {
			confirmed := previous.PublicConfirmed
			audited.PreviousPublicConfirmed = &confirmed
		}
	}
	return audited
}

func appendDNSZoneEvidence(ctx context.Context, tx accountSessionTransaction, change dnszone.Change,
	changeID publicid.ID, record dnsZoneChangeRecord) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return dnszone.ErrInvalid
	}
	var before [32]byte
	var beforeArgument any
	var err error
	if record.Previous != nil {
		if before, err = dnsZoneSemanticHash(*record.Previous); err != nil {
			return err
		}
		beforeArgument = before[:]
	}
	after, err := dnsZoneSemanticHash(record.Zone)
	if err != nil {
		return err
	}
	networkID := change.Scope.NetworkID().String()
	payload, err := json.Marshal(dnsZoneAudit(change.Session, networkID, record))
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		NetworkID       string `json:"network_id"`
		ZoneID          string `json:"dns_zone_id"`
		Version         int64  `json:"version"`
		NetworkRevision int64  `json:"network_revision"`
		DNSRevision     int64  `json:"dns_revision"`
	}{networkID, record.Zone.ID, record.Zone.Version, record.NetworkRevision, record.DNSRevision})
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
	zoneID, err := publicid.Parse(record.Zone.ID)
	if err != nil {
		return dnszone.ErrInvalid
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(change.Session.PrincipalID())
	action := dnsZoneAction(change.Operation)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "network_dns_zone", AggregateID: zoneID, AggregateVersion: record.Zone.Version,
		NetworkRevision: record.NetworkRevision, ActorPrincipalID: principal, Action: action,
		Permission: dnsZonePermission, CorrelationID: change.CorrelationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendDNSZoneEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], record.Zone.ID, record.Zone.Version, record.NetworkRevision,
		principal.String(), action, dnsZonePermission, change.CorrelationID.String(), beforeArgument, after[:],
		payload, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return dnszone.ErrInvalid
	}
	return nil
}
