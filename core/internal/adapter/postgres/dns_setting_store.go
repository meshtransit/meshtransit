package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// A Network's DNS settings (schema 221, DNS design D5b).
const (
	readDNSSettingSQL = `SELECT mesh_ops.read_dns_setting_v1(` + sessionArguments +
		`,$10::UUID,$11::UUID)::TEXT`
	changeDNSSettingSQL = `SELECT mesh_ops.change_dns_setting_v1(` + sessionArguments +
		`,$10::UUID,$11::UUID,$12::BIGINT,$13::UUID[],$14::UUID)::TEXT`
	appendDNSSettingEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'network_dns_setting',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,$12::TEXT,
 $13::UUID,$14::BYTEA,$15::BYTEA,$16::JSONB,'network.revision.advanced',$17::JSONB)`

	dnsSettingAction = "network_dns.updated"
)

var _ dnszone.SettingsStore = (*DNSZoneStore)(nil)

type dnsSettingDocument struct {
	SettingID       *string `json:"setting_id"`
	Version         int64   `json:"version"`
	UnmanagedGroups []struct {
		ID   string `json:"group_id"`
		Name string `json:"name"`
	} `json:"unmanaged_groups"`
}

func (document dnsSettingDocument) settings() (dnszone.Settings, error) {
	if document.Version < 0 || (document.Version == 0) != (document.SettingID == nil) ||
		len(document.UnmanagedGroups) > dnszone.MaximumUnmanagedGroups {
		return dnszone.Settings{}, dnszone.ErrInvalid
	}
	settings := dnszone.Settings{Version: document.Version, UnmanagedGroups: []dnszone.Group{}}
	for _, listed := range document.UnmanagedGroups {
		id, err := devicegroup.ParseID(listed.ID)
		if err != nil || listed.Name == "" {
			return dnszone.Settings{}, dnszone.ErrInvalid
		}
		settings.UnmanagedGroups = append(settings.UnmanagedGroups, dnszone.Group{ID: id, Name: listed.Name,
			State: "active"})
	}
	return settings, nil
}

// ReadSettings reads the Network's DNS settings (network.read).
func (store *DNSZoneStore) ReadSettings(ctx context.Context, session accountsession.Session,
	scope network.Scope,
) (_ dnszone.Settings, resultErr error) {
	if !session.IsValid() || !scope.IsValid() {
		return dnszone.Settings{}, dnszone.ErrInvalid
	}
	tx, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return dnszone.Settings{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, readDNSSettingSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String())...).Scan(&encoded); err != nil {
		return dnszone.Settings{}, dnsZoneDatabaseError(err)
	}
	var document dnsSettingDocument
	if err := decodeDNSZoneJSON([]byte(encoded), &document); err != nil {
		return dnszone.Settings{}, dnszone.ErrInvalid
	}
	return document.settings()
}

type dnsSettingChangeRecord struct {
	Setting         dnsSettingDocument  `json:"setting"`
	Previous        *dnsSettingDocument `json:"previous"`
	Changed         bool                `json:"changed"`
	NetworkRevision int64               `json:"network_revision"`
	DNSRevision     int64               `json:"dns_revision"`
	RoleBindingID   *string             `json:"role_binding_id"`
}

// ChangeSettings sets the unmanaged Device Groups (dns.manage) at the
// expected version. A change commits with its evidence on the Network
// stream and wakes map sessions at once.
func (store *DNSZoneStore) ChangeSettings(ctx context.Context, change dnszone.SettingsChange) (
	_ dnszone.SettingsResult, resultErr error,
) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.CorrelationID.IsValid() ||
		change.ExpectedVersion < 0 || len(change.UnmanagedGroups) > dnszone.MaximumUnmanagedGroups {
		return dnszone.SettingsResult{}, dnszone.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return dnszone.SettingsResult{}, dnszone.ErrUnavailable
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
		return dnszone.SettingsResult{}, err
	}
	groups := make([]string, 0, len(change.UnmanagedGroups))
	for _, group := range change.UnmanagedGroups {
		groups = append(groups, group.String())
	}
	var encoded string
	if err := tx.QueryRow(ctx, changeDNSSettingSQL, append(sessionQueryArguments(change.Session),
		change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), change.ExpectedVersion, groups,
		changeID.String())...).Scan(&encoded); err != nil {
		return dnszone.SettingsResult{}, dnsZoneDatabaseError(err)
	}
	var record dnsSettingChangeRecord
	if err := decodeDNSZoneJSON([]byte(encoded), &record); err != nil {
		return dnszone.SettingsResult{}, dnszone.ErrInvalid
	}
	settings, err := record.Setting.settings()
	if err != nil {
		return dnszone.SettingsResult{}, err
	}
	if !record.Changed {
		// Nothing changed: no evidence, no wakeup; the transaction rolls back.
		return dnszone.SettingsResult{Settings: settings}, nil
	}
	if record.Previous == nil || record.Previous.Version != change.ExpectedVersion ||
		settings.Version != change.ExpectedVersion+1 || record.NetworkRevision <= 0 || record.DNSRevision <= 0 ||
		record.Setting.SettingID == nil {
		return dnszone.SettingsResult{}, dnszone.ErrInvalid
	}
	if err := appendDNSSettingEvidence(ctx, tx, change, changeID, record); err != nil {
		return dnszone.SettingsResult{}, errors.Join(dnszone.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return dnszone.SettingsResult{}, errors.Join(dnszone.ErrUnavailable, err)
	}
	committed = true
	return dnszone.SettingsResult{Settings: settings, Changed: true}, nil
}

// dnsSettingHash is the semantic hash of one version of the settings.
func dnsSettingHash(document dnsSettingDocument) ([32]byte, error) {
	groups := make([]string, 0, len(document.UnmanagedGroups))
	for _, group := range document.UnmanagedGroups {
		groups = append(groups, group.ID)
	}
	// By ID: renaming a group changes no setting.
	slices.Sort(groups)
	encoded, err := json.Marshal(struct {
		Version         int64    `json:"version"`
		UnmanagedGroups []string `json:"unmanaged_group_ids"`
	}{document.Version, groups})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func appendDNSSettingEvidence(ctx context.Context, tx accountSessionTransaction, change dnszone.SettingsChange,
	changeID publicid.ID, record dnsSettingChangeRecord,
) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return dnszone.ErrInvalid
	}
	settingID, err := publicid.Parse(*record.Setting.SettingID)
	if err != nil {
		return dnszone.ErrInvalid
	}
	var before [32]byte
	var beforeArgument any
	if record.Previous.Version > 0 {
		if before, err = dnsSettingHash(*record.Previous); err != nil {
			return err
		}
		beforeArgument = before[:]
	}
	after, err := dnsSettingHash(record.Setting)
	if err != nil {
		return err
	}
	binding := ""
	if record.RoleBindingID != nil {
		binding = *record.RoleBindingID
	}
	networkID := change.Scope.NetworkID().String()
	groupIDs := func(document dnsSettingDocument) []string {
		ids := make([]string, 0, len(document.UnmanagedGroups))
		for _, group := range document.UnmanagedGroups {
			ids = append(ids, group.ID)
		}
		return ids
	}
	payload, err := json.Marshal(struct {
		NetworkID         string   `json:"network_id"`
		SessionID         string   `json:"session_id"`
		RoleBindingID     string   `json:"role_binding_id,omitempty"`
		Version           int64    `json:"version"`
		UnmanagedGroups   []string `json:"unmanaged_group_ids"`
		PreviousUnmanaged []string `json:"previous_unmanaged_group_ids"`
	}{networkID, change.Session.ID().String(), binding, record.Setting.Version, groupIDs(record.Setting),
		groupIDs(*record.Previous)})
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		NetworkID       string `json:"network_id"`
		SettingID       string `json:"dns_setting_id"`
		Version         int64  `json:"version"`
		NetworkRevision int64  `json:"network_revision"`
		DNSRevision     int64  `json:"dns_revision"`
	}{networkID, settingID.String(), record.Setting.Version, record.NetworkRevision, record.DNSRevision})
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
	principal := publicid.ID(change.Session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "network_dns_setting", AggregateID: settingID, AggregateVersion: record.Setting.Version,
		NetworkRevision: record.NetworkRevision, ActorPrincipalID: principal, Action: dnsSettingAction,
		Permission: dnsZonePermission, CorrelationID: change.CorrelationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendDNSSettingEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], settingID.String(), record.Setting.Version, record.NetworkRevision,
		principal.String(), dnsSettingAction, dnsZonePermission, change.CorrelationID.String(), beforeArgument,
		after[:], payload, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return dnszone.ErrInvalid
	}
	return nil
}
