package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

// The service names of a running share (schema 220, DNS design D3 §19).
const (
	readContractServiceNamesSQL = `SELECT mesh_ops.read_contract_service_names_v1(` + sessionArguments +
		`,$10::UUID,$11::UUID,$12::UUID)::TEXT`
	replaceContractServiceNamesSQL = `SELECT mesh_ops.replace_contract_service_names_v1(` + sessionArguments +
		`,$10::UUID,$11::UUID,$12::UUID,$13::BIGINT,$14::TEXT[],$15::UUID)::TEXT`
	appendContractServiceNamesEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'trust_contract_service_name_set',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,$12::TEXT,
 $13::UUID,$14::BYTEA,$15::BYTEA,$16::JSONB,'network.revision.advanced',$17::JSONB)`

	contractServiceNamesAction     = "trust_contract.service_names_changed"
	contractServiceNamesPermission = "share.offer"
	// maximumContractDNSNames bounds the consumer's names one read lists.
	maximumContractDNSNames = 100
)

// ContractServiceNameStore reads a running share's service names for either
// side, lets the provider replace its suggestions, and makes a suggestion a
// DNS name of the consumer Network (DNS design D3 §19), through the runtime
// pool. The SQL functions authorize each call for the session.
type ContractServiceNameStore struct {
	zones   *DNSZoneStore
	planner ServiceNamePlanner
}

// NewContractServiceNameStore uses the runtime pool; planner checks and plans
// the DNS names a suggestion becomes.
func NewContractServiceNameStore(pool *Pool, options AccountSessionOptions, planner ServiceNamePlanner) (
	*ContractServiceNameStore, error,
) {
	zones, err := NewDNSZoneStore(pool, options)
	if err != nil || planner == nil {
		return nil, sharing.ErrUnavailable
	}
	return &ContractServiceNameStore{zones: zones, planner: planner}, nil
}

// contractServiceNamesDatabaseError maps the schema 220 functions' errors;
// the DNS ones keep their own.
func contractServiceNamesDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return sharing.ErrForbidden
		case "P0002":
			return sharing.ErrNotFound
		case "MTZ20":
			return sharing.ErrServiceNamesChanged
		case "MTZ21":
			return sharing.ErrContractEnded
		case "22023", "22P02":
			return sharing.ErrInvalidManagementRequest
		}
	}
	return errors.Join(sharing.ErrUnavailable, err)
}

type contractServiceNamesDocument struct {
	ContractID string    `json:"contract_id"`
	Side       string    `json:"side"`
	State      string    `json:"state"`
	ExpiresAt  time.Time `json:"expires_at"`
	Version    int64     `json:"version"`
	Names      []string  `json:"names"`
	ShareID    *string   `json:"share_id"`
	DNSNames   []struct {
		ID     string `json:"dns_name_id"`
		ZoneID string `json:"dns_zone_id"`
		FQDN   string `json:"fqdn"`
	} `json:"dns_names"`
}

func (document contractServiceNamesDocument) names(contractID sharing.ContractID) (sharing.ContractServiceNames,
	error,
) {
	invalid := sharing.ContractServiceNames{}
	if document.ContractID != contractID.String() || (document.Side != "provider" && document.Side != "consumer") ||
		document.State == "" || document.ExpiresAt.IsZero() || document.Version < 0 ||
		len(document.Names) > sharing.MaximumServiceNames || len(document.DNSNames) > maximumContractDNSNames ||
		(document.Side == "provider") != (document.ShareID == nil) ||
		(document.Side == "provider" && len(document.DNSNames) != 0) {
		return invalid, sharing.ErrUnavailable
	}
	result := sharing.ContractServiceNames{
		ContractID: contractID, Provider: document.Side == "provider", State: document.State,
		ExpiresAt: document.ExpiresAt, Version: document.Version,
		Names: make([]sharing.ServiceName, 0, len(document.Names)),
	}
	for _, value := range document.Names {
		name, err := sharing.ParseServiceName(value)
		if err != nil {
			return invalid, sharing.ErrUnavailable
		}
		result.Names = append(result.Names, name)
	}
	if document.ShareID != nil {
		share, err := sharing.ParseImportedResourceID(*document.ShareID)
		if err != nil {
			return invalid, sharing.ErrUnavailable
		}
		result.ShareID = share
	}
	for _, listed := range document.DNSNames {
		nameID, nameErr := publicid.Parse(listed.ID)
		zoneID, zoneErr := publicid.Parse(listed.ZoneID)
		if nameErr != nil || zoneErr != nil || listed.FQDN == "" {
			return invalid, sharing.ErrUnavailable
		}
		result.DNSNames = append(result.DNSNames, sharing.ContractDNSName{ID: nameID, ZoneID: zoneID, FQDN: listed.FQDN})
	}
	return result, nil
}

func readContractServiceNames(ctx context.Context, tx accountSessionTransaction, session accountsession.Session,
	scope network.Scope, contractID sharing.ContractID,
) (sharing.ContractServiceNames, error) {
	var encoded string
	if err := tx.QueryRow(ctx, readContractServiceNamesSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String(), contractID.String())...).Scan(&encoded); err != nil {
		return sharing.ContractServiceNames{}, contractServiceNamesDatabaseError(err)
	}
	var document contractServiceNamesDocument
	if err := decodeDNSZoneJSON([]byte(encoded), &document); err != nil {
		return sharing.ContractServiceNames{}, sharing.ErrUnavailable
	}
	return document.names(contractID)
}

// begin opens one unit of work in scope; its errors are sharing errors.
func (store *ContractServiceNameStore) begin(ctx context.Context, scope network.Scope) (accountSessionTransaction,
	func(*error), error,
) {
	if ctx == nil || store == nil || store.zones == nil || !scope.IsValid() {
		return nil, func(*error) {}, sharing.ErrInvalidManagementRequest
	}
	tx, err := store.zones.begin(ctx, scope)
	done := func(resultErr *error) {
		if tx != nil {
			*resultErr = errors.Join(*resultErr, rollbackAccountSessionTransaction(tx))
		}
	}
	if err != nil {
		if errors.Is(err, dnszone.ErrForbidden) {
			return tx, done, sharing.ErrForbidden
		}
		return tx, done, errors.Join(sharing.ErrUnavailable, err)
	}
	return tx, done, nil
}

// ContractServiceNames reads a running share's service names for the
// Network of scope, its provider or consumer (share.read).
func (store *ContractServiceNameStore) ContractServiceNames(ctx context.Context, session accountsession.Session,
	scope network.Scope, contractID sharing.ContractID,
) (_ sharing.ContractServiceNames, resultErr error) {
	if !session.IsValid() || !contractID.IsValid() {
		return sharing.ContractServiceNames{}, sharing.ErrInvalidManagementRequest
	}
	tx, done, err := store.begin(ctx, scope)
	defer done(&resultErr)
	if err != nil {
		return sharing.ContractServiceNames{}, err
	}
	return readContractServiceNames(ctx, tx, session, scope, contractID)
}

type replacedContractServiceNamesDocument struct {
	ContractID      string    `json:"contract_id"`
	Changed         bool      `json:"changed"`
	SetID           string    `json:"set_id"`
	State           string    `json:"state"`
	ExpiresAt       time.Time `json:"expires_at"`
	Version         int64     `json:"version"`
	Names           []string  `json:"names"`
	PreviousVersion int64     `json:"previous_version"`
	PreviousNames   []string  `json:"previous_names"`
	NetworkRevision int64     `json:"network_revision"`
	RoleBindingID   *string   `json:"role_binding_id"`
}

// ReplaceContractServiceNames sets the provider's suggestions on a running
// contract (share.offer) when expectedVersion is still current, and reports
// whether anything changed. A change commits with its evidence on the
// provider Network's stream, at its current revision: suggestions are no
// part of a map, so no map rebuilds.
func (store *ContractServiceNameStore) ReplaceContractServiceNames(ctx context.Context,
	session accountsession.Session, scope network.Scope, contractID sharing.ContractID, expectedVersion int64,
	names []sharing.ServiceName, correlationID publicid.ID,
) (_ sharing.ContractServiceNames, _ bool, resultErr error) {
	if !session.IsValid() || !contractID.IsValid() || expectedVersion < 0 || !correlationID.IsValid() ||
		len(names) > sharing.MaximumServiceNames {
		return sharing.ContractServiceNames{}, false, sharing.ErrInvalidManagementRequest
	}
	values := make([]string, 0, len(names))
	for _, name := range names {
		if !name.IsValid() {
			return sharing.ContractServiceNames{}, false, sharing.ErrInvalidManagementRequest
		}
		values = append(values, name.String())
	}
	changeID, err := publicid.New()
	if err != nil {
		return sharing.ContractServiceNames{}, false, sharing.ErrUnavailable
	}
	tx, done, err := store.begin(ctx, scope)
	defer done(&resultErr)
	if err != nil {
		return sharing.ContractServiceNames{}, false, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, replaceContractServiceNamesSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String(), contractID.String(), expectedVersion, values,
		changeID.String())...).Scan(&encoded); err != nil {
		return sharing.ContractServiceNames{}, false, contractServiceNamesDatabaseError(err)
	}
	var document replacedContractServiceNamesDocument
	if err := decodeDNSZoneJSON([]byte(encoded), &document); err != nil {
		return sharing.ContractServiceNames{}, false, sharing.ErrUnavailable
	}
	result, err := contractServiceNamesDocument{
		ContractID: document.ContractID, Side: "provider", State: document.State, ExpiresAt: document.ExpiresAt,
		Version: document.Version, Names: document.Names,
	}.names(contractID)
	if err != nil {
		return sharing.ContractServiceNames{}, false, err
	}
	if !document.Changed {
		return result, false, nil
	}
	if document.Version != document.PreviousVersion+1 || document.NetworkRevision <= 0 {
		return sharing.ContractServiceNames{}, false, sharing.ErrUnavailable
	}
	if err := appendContractServiceNamesEvidence(ctx, tx, session, scope, correlationID, changeID,
		document); err != nil {
		return sharing.ContractServiceNames{}, false, errors.Join(sharing.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return sharing.ContractServiceNames{}, false, errors.Join(sharing.ErrUnavailable, err)
	}
	return result, true, nil
}

// contractServiceNamesHash is the semantic hash of one version of a
// contract's suggestions.
func contractServiceNamesHash(contractID string, version int64, names []string) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		ContractID string   `json:"trust_contract_id"`
		Version    int64    `json:"version"`
		Names      []string `json:"names"`
	}{contractID, version, names})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func appendContractServiceNamesEvidence(ctx context.Context, tx accountSessionTransaction,
	session accountsession.Session, scope network.Scope, correlationID, changeID publicid.ID,
	document replacedContractServiceNamesDocument,
) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return sharing.ErrUnavailable
	}
	setID, err := publicid.Parse(document.SetID)
	if err != nil {
		return sharing.ErrUnavailable
	}
	binding := ""
	if document.RoleBindingID != nil {
		binding = *document.RoleBindingID
	}
	var before [32]byte
	var beforeArgument any
	if document.PreviousVersion > 0 {
		if before, err = contractServiceNamesHash(document.ContractID, document.PreviousVersion,
			document.PreviousNames); err != nil {
			return err
		}
		beforeArgument = before[:]
	}
	after, err := contractServiceNamesHash(document.ContractID, document.Version, document.Names)
	if err != nil {
		return err
	}
	networkID := scope.NetworkID().String()
	payload, err := json.Marshal(struct {
		NetworkID     string   `json:"network_id"`
		SessionID     string   `json:"session_id"`
		RoleBindingID string   `json:"role_binding_id,omitempty"`
		ContractID    string   `json:"trust_contract_id"`
		Version       int64    `json:"version"`
		Names         []string `json:"names"`
		PreviousNames []string `json:"previous_names"`
	}{networkID, session.ID().String(), binding, document.ContractID, document.Version, document.Names,
		document.PreviousNames})
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		NetworkID       string `json:"network_id"`
		ContractID      string `json:"trust_contract_id"`
		Version         int64  `json:"version"`
		NetworkRevision int64  `json:"network_revision"`
	}{networkID, document.ContractID, document.Version, document.NetworkRevision})
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
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "trust_contract_service_name_set", AggregateID: setID, AggregateVersion: document.Version,
		NetworkRevision: document.NetworkRevision, ActorPrincipalID: principal, Action: contractServiceNamesAction,
		Permission: contractServiceNamesPermission, CorrelationID: correlationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendContractServiceNamesEvidenceSQL, streamID, eventID.String(), outboxID.String(),
		sequence, previousHash[:], eventHash[:], setID.String(), document.Version, document.NetworkRevision,
		principal.String(), contractServiceNamesAction, contractServiceNamesPermission, correlationID.String(),
		beforeArgument, after[:], payload, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return sharing.ErrUnavailable
	}
	return nil
}

// UseContractServiceName makes one of a running share's suggestions a DNS
// name of the consumer Network that points at the share (dns.manage), as an
// accept does: in the longest zone that covers it or a zone of its own. It
// returns the name and its zone.
func (store *ContractServiceNameStore) UseContractServiceName(ctx context.Context, session accountsession.Session,
	scope network.Scope, contractID sharing.ContractID, name sharing.ServiceName, correlationID publicid.ID,
) (_ dnszone.Name, _ dnszone.Zone, resultErr error) {
	if !session.IsValid() || !contractID.IsValid() || !name.IsValid() || !correlationID.IsValid() {
		return dnszone.Name{}, dnszone.Zone{}, sharing.ErrInvalidManagementRequest
	}
	changeID, err := publicid.New()
	if err != nil {
		return dnszone.Name{}, dnszone.Zone{}, sharing.ErrUnavailable
	}
	tx, done, err := store.begin(ctx, scope)
	defer done(&resultErr)
	if err != nil {
		return dnszone.Name{}, dnszone.Zone{}, err
	}
	current, err := readContractServiceNames(ctx, tx, session, scope, contractID)
	if err != nil {
		return dnszone.Name{}, dnszone.Zone{}, err
	}
	if current.Provider {
		return dnszone.Name{}, dnszone.Zone{}, sharing.ErrForbidden
	}
	if !current.Running(time.Now()) {
		return dnszone.Name{}, dnszone.Zone{}, sharing.ErrContractEnded
	}
	if !current.Suggests(name) {
		return dnszone.Name{}, dnszone.Zone{}, sharing.ErrServiceNameNotSuggested
	}
	made, err := applyServiceName(ctx, tx, store.planner, session, scope, name.String(), current.ShareID,
		correlationID, changeID)
	if err != nil {
		return dnszone.Name{}, dnszone.Zone{}, err
	}
	if made.Changed {
		if _, err := deferDNSChangeWakeup(ctx, tx, changeID); err != nil {
			return dnszone.Name{}, dnszone.Zone{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return dnszone.Name{}, dnszone.Zone{}, errors.Join(dnszone.ErrUnavailable, err)
	}
	return made.Name, made.Zone, nil
}
