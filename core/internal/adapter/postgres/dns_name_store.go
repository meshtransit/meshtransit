package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const listDNSNamesSQL = `SELECT mesh_ops.list_dns_names_v1(` + sessionArguments + `,$10::UUID,$11::UUID,$12::UUID,
 NULLIF($13::TEXT,'')::UUID,NULLIF($14::TEXT,''),$15::INTEGER)::TEXT`

const readDNSNameSQL = `SELECT mesh_ops.read_dns_name_v1(` + sessionArguments + `,$10::UUID,$11::UUID,$12::UUID,
 $13::UUID)::TEXT`

const changeDNSNamesSQL = `SELECT mesh_ops.change_dns_names_v1(` + sessionArguments + `,$10::UUID,$11::UUID,
 $12::UUID,$13::JSONB,$14::INTEGER,$15::INTEGER,$16::INTEGER,$17::UUID)::TEXT`

const appendDNSNameEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network_dns_name',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,$12::TEXT,
 $13::UUID,$14::BYTEA,$15::BYTEA,$16::JSONB,'network.revision.advanced',$17::JSONB)`

// maximumDNSNameDocumentBytes bounds one page of names or one change of 100
// names with their previous state.
const maximumDNSNameDocumentBytes = 4 << 20

// dnsNameDatabaseError maps a name call's error; an error of one operation
// of a change names its position in the detail.
func dnsNameDatabaseError(err error) error {
	mapped := dnsZoneDatabaseError(err)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) {
		return mapped
	}
	if pgError.Code == "MTZ0F" {
		mapped = dnszone.ErrNameNotFound
	}
	if index, parseErr := strconv.Atoi(pgError.Detail); parseErr == nil && index >= 0 &&
		index < dnszone.MaximumNameOperations && strconv.Itoa(index) == pgError.Detail {
		return &dnszone.OperationError{Index: index, Err: mapped}
	}
	return mapped
}

// dnsNameDocument is one name as stored, with its label in its zone and
// what Core knows of a target Device.
type dnsNameDocument struct {
	ID          string    `json:"name_id"`
	ZoneID      string    `json:"zone_id"`
	FQDN        string    `json:"fqdn"`
	Label       string    `json:"label"`
	Kind        string    `json:"kind"`
	DeviceID    *string   `json:"device_id"`
	DeviceName  *string   `json:"device_name"`
	DeviceState *string   `json:"device_state"`
	Addresses   []string  `json:"addresses"`
	CNAME       *string   `json:"cname"`
	State       string    `json:"state"`
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (document dnsNameDocument) name(allowDeleted bool) (dnszone.Name, error) {
	id, idErr := dnszone.ParseNameID(document.ID)
	zone, zoneErr := dnszone.ParseID(document.ZoneID)
	kind := dnszone.NameKind(document.Kind)
	if idErr != nil || zoneErr != nil || !kind.IsKnown() || document.FQDN == "" || len(document.FQDN) > 253 ||
		document.Label == "" || document.Version <= 0 || document.CreatedAt.IsZero() ||
		document.UpdatedAt.Before(document.CreatedAt) ||
		(document.State != "active" && (document.State != "deleted" || !allowDeleted)) {
		return dnszone.Name{}, dnszone.ErrInvalid
	}
	name := dnszone.Name{
		ID: id, ZoneID: zone, FQDN: document.FQDN, Label: document.Label, Kind: kind,
		Deleted: document.State == "deleted", Version: document.Version,
		CreatedAt: document.CreatedAt.UTC(), UpdatedAt: document.UpdatedAt.UTC(),
	}
	if document.DeviceID != nil {
		device, err := node.ParseID(*document.DeviceID)
		if err != nil || document.DeviceState == nil || *document.DeviceState == "" {
			return dnszone.Name{}, dnszone.ErrInvalid
		}
		name.Target.DeviceID = device
		name.Device = &dnszone.NameDevice{State: *document.DeviceState}
		if document.DeviceName != nil {
			name.Device.Name = *document.DeviceName
		}
	}
	for _, text := range document.Addresses {
		address, err := netip.ParseAddr(text)
		if err != nil {
			return dnszone.Name{}, dnszone.ErrInvalid
		}
		name.Target.Addresses = append(name.Target.Addresses, address)
	}
	if document.CNAME != nil {
		name.Target.CNAME = *document.CNAME
	}
	// The stored target is one the database's checks accept.
	if (dnszone.NameDefinition{Kind: kind, Target: name.Target}).Validate() != nil {
		return dnszone.Name{}, dnszone.ErrInvalid
	}
	return name, nil
}

// ListNames returns one page of a zone's active names (network.read).
func (store *DNSZoneStore) ListNames(ctx context.Context, session accountsession.Session, scope network.Scope,
	zoneID dnszone.ID, after dnszone.NameID, prefix string, limit int) (dnszone.NameListing, error) {
	if !session.IsValid() || !scope.IsValid() || !zoneID.IsValid() || limit < 1 || limit > dnszone.MaximumPage {
		return dnszone.NameListing{}, dnszone.ErrInvalid
	}
	afterText := ""
	if after != (dnszone.NameID{}) {
		afterText = after.String()
	}
	var encoded string
	if err := store.readNames(ctx, scope, func(tx accountSessionTransaction) error {
		return tx.QueryRow(ctx, listDNSNamesSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), zoneID.String(), afterText, prefix,
			limit)...).Scan(&encoded)
	}); err != nil {
		return dnszone.NameListing{}, err
	}
	var document struct {
		Names   []dnsNameDocument `json:"names"`
		HasMore bool              `json:"has_more"`
		Zone    dnsZoneDocument   `json:"zone"`
		dnsZoneAbilitiesDocument
	}
	if err := decodeDNSNameJSON([]byte(encoded), &document); err != nil || len(document.Names) > limit {
		return dnszone.NameListing{}, dnszone.ErrInvalid
	}
	zone, err := document.Zone.zone(false)
	if err != nil || zone.ID != zoneID {
		return dnszone.NameListing{}, dnszone.ErrInvalid
	}
	listing := dnszone.NameListing{Zone: zone, Names: make([]dnszone.Name, 0, len(document.Names)),
		HasMore: document.HasMore, Abilities: dnszone.Abilities{CanManage: document.CanManage}}
	for _, item := range document.Names {
		name, err := item.name(false)
		if err != nil || name.ZoneID != zoneID {
			return dnszone.NameListing{}, dnszone.ErrInvalid
		}
		listing.Names = append(listing.Names, name)
	}
	return listing, nil
}

// ReadName returns one active name of a zone (network.read).
func (store *DNSZoneStore) ReadName(ctx context.Context, session accountsession.Session, scope network.Scope,
	zoneID dnszone.ID, nameID dnszone.NameID) (dnszone.NameReading, error) {
	if !session.IsValid() || !scope.IsValid() || !zoneID.IsValid() || !nameID.IsValid() {
		return dnszone.NameReading{}, dnszone.ErrInvalid
	}
	var encoded string
	if err := store.readNames(ctx, scope, func(tx accountSessionTransaction) error {
		return tx.QueryRow(ctx, readDNSNameSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), zoneID.String(),
			nameID.String())...).Scan(&encoded)
	}); err != nil {
		return dnszone.NameReading{}, err
	}
	var document struct {
		Name dnsNameDocument `json:"name"`
		dnsZoneAbilitiesDocument
	}
	if err := decodeDNSNameJSON([]byte(encoded), &document); err != nil {
		return dnszone.NameReading{}, dnszone.ErrInvalid
	}
	name, err := document.Name.name(false)
	if err != nil || name.ID != nameID || name.ZoneID != zoneID {
		return dnszone.NameReading{}, dnszone.ErrInvalid
	}
	return dnszone.NameReading{Name: name, Abilities: dnszone.Abilities{CanManage: document.CanManage}}, nil
}

// readNames runs one read-only query in the Network scope and rolls back.
func (store *DNSZoneStore) readNames(ctx context.Context, scope network.Scope,
	query func(accountSessionTransaction) error) (resultErr error) {
	tx, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return err
	}
	if err := query(tx); err != nil {
		return dnsNameDatabaseError(err)
	}
	return nil
}

func decodeDNSNameJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumDNSNameDocumentBytes {
		return dnszone.ErrInvalid
	}
	return decodeStrictJSON(string(encoded), maximumDNSNameDocumentBytes, target)
}

// dnsNameOperationDocument is one operation as change_dns_names_v1 reads it.
type dnsNameOperationDocument struct {
	Operation       string   `json:"op"`
	NameID          string   `json:"name_id"`
	ExpectedVersion int64    `json:"expected_version,omitempty"`
	Label           string   `json:"label,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	DeviceID        string   `json:"device_id,omitempty"`
	Addresses       []string `json:"addresses,omitempty"`
	CNAME           string   `json:"cname,omitempty"`
}

func dnsNameOperationsJSON(operations []dnszone.NameOperation) ([]byte, error) {
	documents := make([]dnsNameOperationDocument, 0, len(operations))
	for _, operation := range operations {
		definition := operation.Definition
		document := dnsNameOperationDocument{
			Operation: string(operation.Operation), NameID: operation.NameID.String(),
			ExpectedVersion: operation.ExpectedVersion, Label: definition.Label, Kind: string(definition.Kind),
			CNAME: definition.Target.CNAME,
		}
		if definition.Target.DeviceID.IsValid() {
			document.DeviceID = definition.Target.DeviceID.String()
		}
		for _, address := range definition.Target.Addresses {
			document.Addresses = append(document.Addresses, address.String())
		}
		documents = append(documents, document)
	}
	return json.Marshal(documents)
}

type dnsNameOutcomeDocument struct {
	Index     int              `json:"index"`
	Operation string           `json:"operation"`
	Name      dnsNameDocument  `json:"name"`
	Previous  *dnsNameDocument `json:"previous"`
	Changed   bool             `json:"changed"`
}

type dnsNameChangeRecord struct {
	Results         []dnsNameOutcomeDocument `json:"results"`
	Changed         bool                     `json:"changed"`
	NetworkRevision int64                    `json:"network_revision"`
	DNSRevision     int64                    `json:"dns_revision"`
	RoleBindingID   *string                  `json:"role_binding_id"`
}

// outcome checks one result against the operation it answers: the same
// name, deleted by a delete, one version past the expected one when changed.
func (document dnsNameOutcomeDocument) outcome(index int, operation dnszone.NameOperation) (dnszone.NameOutcome,
	error) {
	deleted := operation.Operation == dnszone.OperationDelete
	name, err := document.Name.name(deleted)
	if err != nil || document.Index != index || document.Operation != string(operation.Operation) ||
		name.ID != operation.NameID || name.Deleted != (deleted && document.Changed) ||
		(document.Previous == nil) != (operation.Operation == dnszone.OperationCreate) ||
		(!document.Changed && operation.Operation != dnszone.OperationUpdate) {
		return dnszone.NameOutcome{}, dnszone.ErrInvalid
	}
	// A changed name holds what the operation asked for.
	if document.Changed && operation.Operation != dnszone.OperationDelete &&
		!sameNameTarget(name, operation.Definition) {
		return dnszone.NameOutcome{}, dnszone.ErrInvalid
	}
	if operation.Operation == dnszone.OperationCreate && name.Label != operation.Definition.Label {
		return dnszone.NameOutcome{}, dnszone.ErrInvalid
	}
	outcome := dnszone.NameOutcome{Index: index, Operation: operation.Operation, Name: name,
		Changed: document.Changed}
	if document.Previous != nil {
		previous, err := document.Previous.name(false)
		if err != nil || previous.ID != name.ID || previous.Version != operation.ExpectedVersion ||
			(document.Changed && name.Version != previous.Version+1) {
			return dnszone.NameOutcome{}, dnszone.ErrInvalid
		}
		outcome.Previous = &previous
	}
	return outcome, nil
}

// sameNameTarget reports a stored name with the kind and target a
// definition asks for.
func sameNameTarget(name dnszone.Name, definition dnszone.NameDefinition) bool {
	return name.Kind == definition.Kind && name.Target.DeviceID == definition.Target.DeviceID &&
		name.Target.CNAME == definition.Target.CNAME && slices.Equal(name.Target.Addresses, definition.Target.Addresses)
}

// ChangeNames authorizes dns.manage, applies the operations and commits
// them with one audit event per changed name.
func (store *DNSZoneStore) ChangeNames(ctx context.Context, change dnszone.NameChange) (_ dnszone.NameResult,
	resultErr error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.ZoneID.IsValid() ||
		!change.CorrelationID.IsValid() || len(change.Operations) == 0 ||
		len(change.Operations) > dnszone.MaximumNameOperations {
		return dnszone.NameResult{}, dnszone.ErrInvalid
	}
	operations, err := dnsNameOperationsJSON(change.Operations)
	if err != nil {
		return dnszone.NameResult{}, dnszone.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return dnszone.NameResult{}, dnszone.ErrUnavailable
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
		return dnszone.NameResult{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, changeDNSNamesSQL, append(sessionQueryArguments(change.Session),
		change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), change.ZoneID.String(),
		operations, change.Limits.NamesPerZone, change.Limits.NamesPerNetwork, change.Limits.HostNamesPerNetwork,
		changeID.String())...).Scan(&encoded); err != nil {
		return dnszone.NameResult{}, dnsNameDatabaseError(err)
	}
	var record dnsNameChangeRecord
	if err := decodeDNSNameJSON([]byte(encoded), &record); err != nil ||
		len(record.Results) != len(change.Operations) ||
		(record.Changed && (record.NetworkRevision <= 0 || record.DNSRevision <= 0)) {
		return dnszone.NameResult{}, dnszone.ErrInvalid
	}
	result := dnszone.NameResult{Outcomes: make([]dnszone.NameOutcome, 0, len(record.Results)),
		Changed: record.Changed}
	anyChanged := false
	for index, item := range record.Results {
		outcome, err := item.outcome(index, change.Operations[index])
		if err != nil || outcome.Name.ZoneID != change.ZoneID {
			return dnszone.NameResult{}, dnszone.ErrInvalid
		}
		anyChanged = anyChanged || outcome.Changed
		result.Outcomes = append(result.Outcomes, outcome)
	}
	if anyChanged != record.Changed {
		return dnszone.NameResult{}, dnszone.ErrInvalid
	}
	if !record.Changed {
		// Nothing changed: no evidence, no wakeup; the transaction rolls back.
		return result, nil
	}
	for _, item := range record.Results {
		if !item.Changed {
			continue
		}
		if err := appendDNSNameEvidence(ctx, tx, change, changeID, record, item); err != nil {
			return dnszone.NameResult{}, errors.Join(dnszone.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return dnszone.NameResult{}, errors.Join(dnszone.ErrUnavailable, err)
	}
	committed = true
	return result, nil
}

func dnsNameAction(operation string) string {
	switch operation {
	case "create":
		return "dns_name.created"
	case "update":
		return "dns_name.updated"
	default:
		return "dns_name.deleted"
	}
}

// dnsNameTarget is a name's kind and target as its hash and audit record
// it.
type dnsNameTarget struct {
	Kind      string   `json:"kind"`
	DeviceID  string   `json:"device_id,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	CNAME     string   `json:"cname,omitempty"`
}

func dnsNameTargetOf(document dnsNameDocument) dnsNameTarget {
	target := dnsNameTarget{Kind: document.Kind, Addresses: slices.Clone(document.Addresses)}
	if document.DeviceID != nil {
		target.DeviceID = *document.DeviceID
	}
	if document.CNAME != nil {
		target.CNAME = *document.CNAME
	}
	return target
}

// dnsNameSemanticHash commits to what a name decides: its identity, zone,
// name, state, kind and target.
func dnsNameSemanticHash(document dnsNameDocument) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		NameID string        `json:"name_id"`
		ZoneID string        `json:"zone_id"`
		FQDN   string        `json:"fqdn"`
		State  string        `json:"state"`
		Target dnsNameTarget `json:"target"`
	}{document.ID, document.ZoneID, document.FQDN, document.State, dnsNameTargetOf(document)})
	return sha256.Sum256(encoded), err
}

type dnsNameAuditPayload struct {
	NetworkID      string         `json:"network_id"`
	SessionID      string         `json:"session_id"`
	RoleBindingID  string         `json:"role_binding_id,omitempty"`
	ZoneID         string         `json:"dns_zone_id"`
	NameID         string         `json:"dns_name_id"`
	FQDN           string         `json:"fqdn"`
	PublicZone     bool           `json:"public_zone"`
	Target         dnsNameTarget  `json:"target"`
	PreviousTarget *dnsNameTarget `json:"previous_target,omitempty"`
}

func appendDNSNameEvidence(ctx context.Context, tx accountSessionTransaction, change dnszone.NameChange,
	changeID publicid.ID, record dnsNameChangeRecord, item dnsNameOutcomeDocument) error {
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
	binding := ""
	if record.RoleBindingID != nil {
		binding = *record.RoleBindingID
	}
	networkID := change.Scope.NetworkID().String()
	audited := dnsNameAuditPayload{
		NetworkID: networkID, SessionID: change.Session.ID().String(), RoleBindingID: binding,
		ZoneID: item.Name.ZoneID, NameID: item.Name.ID, FQDN: item.Name.FQDN,
		PublicZone: change.ZoneClass == dnszone.ClassPublic, Target: dnsNameTargetOf(item.Name),
	}
	if item.Previous != nil {
		if before, err = dnsNameSemanticHash(*item.Previous); err != nil {
			return err
		}
		beforeArgument = before[:]
		previousTarget := dnsNameTargetOf(*item.Previous)
		audited.PreviousTarget = &previousTarget
	}
	after, err := dnsNameSemanticHash(item.Name)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(audited)
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		NetworkID       string `json:"network_id"`
		ZoneID          string `json:"dns_zone_id"`
		NameID          string `json:"dns_name_id"`
		Version         int64  `json:"version"`
		NetworkRevision int64  `json:"network_revision"`
		DNSRevision     int64  `json:"dns_revision"`
	}{networkID, item.Name.ZoneID, item.Name.ID, item.Name.Version, record.NetworkRevision, record.DNSRevision})
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
	nameID, err := publicid.Parse(item.Name.ID)
	if err != nil {
		return dnszone.ErrInvalid
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(change.Session.PrincipalID())
	action := dnsNameAction(item.Operation)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "network_dns_name", AggregateID: nameID, AggregateVersion: item.Name.Version,
		NetworkRevision: record.NetworkRevision, ActorPrincipalID: principal, Action: action,
		Permission: dnsZonePermission, CorrelationID: change.CorrelationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendDNSNameEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], item.Name.ID, item.Name.Version, record.NetworkRevision,
		principal.String(), action, dnsZonePermission, change.CorrelationID.String(), beforeArgument, after[:],
		payload, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return dnszone.ErrInvalid
	}
	return nil
}
