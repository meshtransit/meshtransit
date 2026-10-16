package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const listDeviceTagsSQL = `SELECT mesh_ops.list_device_tags_v1(` + sessionArguments + `,
 $10::UUID,$11::TIMESTAMPTZ)::TEXT`

const changeDeviceTagSQL = `SELECT mesh_ops.change_device_tag_v1(` + sessionArguments + `,
 $10::UUID,$11::TEXT,$12::UUID,$13::BIGINT,$14::TEXT,$15::TEXT,$16::UUID[],$17::TEXT[],$18::UUID[],
 $19::UUID,$20::TIMESTAMPTZ)::TEXT`

const readNetworkTagOptionsSQL = `SELECT mesh_ops.read_network_tag_options_v1(` + sessionArguments + `,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ)::TEXT`

const readNetworkDeviceTagsSQL = `SELECT mesh_ops.read_network_device_tags_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ)::TEXT`

const changeDeviceTagsSQL = `SELECT mesh_ops.change_device_tags_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::JSONB,$14::UUID[],$15::UUID,$16::TIMESTAMPTZ)::TEXT`

// DeviceTagStore reads and changes the device tag catalog and Device tags
// through the runtime pool. Catalog changes commit with evidence on the
// Workspace stream; tag assignments on the Device's Network stream, with the
// revision wakeup that rebuilds its maps.
type DeviceTagStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ devicetag.Store = (*DeviceTagStore)(nil)

// NewDeviceTagStore uses the runtime pool.
func NewDeviceTagStore(pool *Pool, options AccountSessionOptions) (*DeviceTagStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, devicetag.ErrInvalid
	}
	return &DeviceTagStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func deviceTagDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501", "23503":
			return devicetag.ErrForbidden
		case "P0002":
			return devicetag.ErrNotFound
		case "40001":
			return devicetag.ErrVersionConflict
		case "MTT02":
			return devicetag.ErrTagLimit
		case "MTT03":
			return devicetag.ErrUnknownOwner
		case "MTT04":
			return devicetag.ErrNameTaken
		case "MTT05":
			return devicetag.ErrInUse
		case "MTD06":
			return devicetag.ErrEdgeBudget
		case "22023", "22P02", "23514":
			return devicetag.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return devicetag.ErrForbidden
	}
	return errors.Join(devicetag.ErrUnavailable, err)
}

// begin starts one unit of work, in the Network scope when one is given, and
// reads its time on the database clock, which authorizes it and stamps
// everything it writes.
func (store *DeviceTagStore) begin(ctx context.Context, scope *network.Scope) (accountSessionTransaction,
	time.Time, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, time.Time{}, devicetag.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, time.Time{}, errors.Join(devicetag.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, time.Time{}, errors.Join(devicetag.ErrUnavailable, err)
	}
	if scope != nil {
		var workspaceInternal, networkInternal int64
		if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
			scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
			return tx, time.Time{}, deviceTagDatabaseError(err)
		}
		if workspaceInternal <= 0 || networkInternal <= 0 {
			return tx, time.Time{}, devicetag.ErrForbidden
		}
	}
	at, err := readTransactionTime(ctx, tx.QueryRow)
	if err != nil {
		return tx, time.Time{}, errors.Join(devicetag.ErrUnavailable, err)
	}
	return tx, at, nil
}

func (store *DeviceTagStore) transact(ctx context.Context, scope *network.Scope,
	run func(tx accountSessionTransaction, evaluatedAt time.Time) (bool, error)) (resultErr error) {
	tx, evaluatedAt, err := store.begin(ctx, scope)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return err
	}
	commit, err := run(tx, evaluatedAt)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(devicetag.ErrUnavailable, err)
	}
	return nil
}

type deviceTagDocument struct {
	ID            string    `json:"tag_id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	OwnerGroupIDs []string  `json:"owner_group_ids"`
	OwnerRoles    []string  `json:"owner_roles"`
	DeviceCount   int       `json:"device_count"`
	RuleCount     int       `json:"rule_count"`
	State         string    `json:"state"`
	Version       int64     `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (document deviceTagDocument) tag(allowDeleted bool) (devicetag.Tag, error) {
	id, err := devicetag.ParseID(document.ID)
	if err != nil || (document.State != "active" && (!allowDeleted || document.State != "deleted")) ||
		document.OwnerGroupIDs == nil || document.OwnerRoles == nil {
		return devicetag.Tag{}, devicetag.ErrInvalid
	}
	groups := make([]identitygroup.ID, 0, len(document.OwnerGroupIDs))
	for _, text := range document.OwnerGroupIDs {
		group, err := identitygroup.ParseID(text)
		if err != nil {
			return devicetag.Tag{}, devicetag.ErrInvalid
		}
		groups = append(groups, group)
	}
	tag := devicetag.Tag{
		ID: id, Version: document.Version, DeviceCount: document.DeviceCount, RuleCount: document.RuleCount,
		CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
		Definition: devicetag.Definition{
			Name: document.Name, Description: document.Description, OwnerGroups: groups,
			OwnerRoles: append([]string{}, document.OwnerRoles...),
		}.Canonical(),
	}
	if !tag.IsValid() {
		return devicetag.Tag{}, devicetag.ErrInvalid
	}
	return tag, nil
}

// deviceTagSemanticHash commits to what a tag is and who may apply it.
func deviceTagSemanticHash(document deviceTagDocument) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		TagID       string   `json:"tag_id"`
		Name        string   `json:"name"`
		State       string   `json:"state"`
		OwnerGroups []string `json:"owner_group_ids"`
		OwnerRoles  []string `json:"owner_roles"`
	}{document.ID, document.Name, document.State, document.OwnerGroupIDs, document.OwnerRoles})
	return sha256.Sum256(encoded), err
}

// List authorizes device_tag.read and returns the catalog.
func (store *DeviceTagStore) List(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID) (devicetag.Listing, error) {
	if !session.IsValid() || !workspaceID.IsValid() {
		return devicetag.Listing{}, devicetag.ErrInvalid
	}
	var listing devicetag.Listing
	err := store.transact(ctx, nil, func(tx accountSessionTransaction, at time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listDeviceTagsSQL, append(sessionQueryArguments(session),
			workspaceID.String(), at)...).Scan(&encoded); err != nil {
			return false, deviceTagDatabaseError(err)
		}
		var envelope struct {
			Tags      []deviceTagDocument `json:"tags"`
			CanManage bool                `json:"can_manage"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil || envelope.Tags == nil ||
			len(envelope.Tags) > devicetag.MaximumTags {
			return false, devicetag.ErrInvalid
		}
		listing = devicetag.Listing{Tags: make([]devicetag.Tag, 0, len(envelope.Tags)), CanManage: envelope.CanManage}
		for _, document := range envelope.Tags {
			tag, err := document.tag(false)
			if err != nil {
				return false, err
			}
			listing.Tags = append(listing.Tags, tag)
		}
		return false, nil
	})
	if err != nil {
		return devicetag.Listing{}, err
	}
	return listing, nil
}

type deviceTagChangeRecord struct {
	Tag       deviceTagDocument    `json:"tag"`
	Previous  *deviceTagDocument   `json:"previous"`
	Networks  []advancedNetworkRow `json:"networks"`
	Authority catalogAuthority     `json:"authority"`
}

// Change authorizes device_tag.manage and applies a catalog change.
func (store *DeviceTagStore) Change(ctx context.Context, change devicetag.Change) (devicetag.Result, error) {
	if !change.Session.IsValid() || !change.WorkspaceID.IsValid() || !change.TagID.IsValid() ||
		!change.CorrelationID.IsValid() {
		return devicetag.Result{}, devicetag.ErrInvalid
	}
	definition := change.Definition.Canonical()
	var expected, name, description, groups, roles, rows any
	if change.Operation != devicetag.OperationCreate {
		expected = change.ExpectedVersion
	}
	if change.Operation != devicetag.OperationDelete {
		if !definition.IsValid() ||
			len(change.OwnerRowIDs) != len(definition.OwnerGroups)+len(definition.OwnerRoles) {
			return devicetag.Result{}, devicetag.ErrInvalid
		}
		groupTexts := make([]string, len(definition.OwnerGroups))
		for index, group := range definition.OwnerGroups {
			groupTexts[index] = group.String()
		}
		rowTexts := make([]string, len(change.OwnerRowIDs))
		for index, row := range change.OwnerRowIDs {
			rowTexts[index] = row.String()
		}
		name, description, groups, roles, rows = definition.Name, definition.Description, groupTexts,
			definition.OwnerRoles, rowTexts
	}
	changeID, err := publicid.New()
	if err != nil {
		return devicetag.Result{}, devicetag.ErrUnavailable
	}
	var result devicetag.Result
	err = store.transact(ctx, nil, func(tx accountSessionTransaction, at time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, changeDeviceTagSQL, append(sessionQueryArguments(change.Session),
			change.WorkspaceID.String(), string(change.Operation), change.TagID.String(), expected, name,
			description, groups, roles, rows, changeID.String(), at)...).Scan(&encoded); err != nil {
			return false, deviceTagDatabaseError(err)
		}
		var record deviceTagChangeRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Networks == nil {
			return false, devicetag.ErrInvalid
		}
		deleted := change.Operation == devicetag.OperationDelete
		saved, err := record.Tag.tag(deleted)
		if err != nil || saved.ID != change.TagID ||
			(record.Previous == nil) != (change.Operation == devicetag.OperationCreate) {
			return false, devicetag.ErrInvalid
		}
		networks, err := advancedNetworks(record.Networks)
		if err != nil || (!deleted && len(networks) > 0) {
			return false, devicetag.ErrInvalid
		}
		result = devicetag.Result{Tag: saved, Deleted: deleted, Networks: networks}
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "device_tag", aggregateID: publicid.ID(saved.ID), version: saved.Version,
			action: "device_tag." + map[devicetag.Operation]string{
				devicetag.OperationCreate: "created", devicetag.OperationUpdate: "updated",
				devicetag.OperationDelete: "deleted",
			}[change.Operation],
			permission: "device_tag.manage",
		}
		previousName := ""
		if record.Previous != nil {
			previous, err := record.Previous.tag(false)
			if err != nil || previous.Version != change.ExpectedVersion {
				return false, devicetag.ErrInvalid
			}
			result.Previous = &previous
			hash, err := deviceTagSemanticHash(*record.Previous)
			if err != nil {
				return false, err
			}
			event.before = &hash
			if previous.Name != saved.Name {
				previousName = previous.Name
			}
		}
		if event.after, err = deviceTagSemanticHash(record.Tag); err != nil {
			return false, err
		}
		event.payload = struct {
			WorkspaceID  string           `json:"workspace_id"`
			SessionID    string           `json:"session_id"`
			TagID        string           `json:"tag_id"`
			Name         string           `json:"display_name"`
			PreviousName string           `json:"previous_display_name,omitempty"`
			OwnerGroups  []string         `json:"owner_group_ids"`
			OwnerRoles   []string         `json:"owner_roles"`
			Networks     int              `json:"rebuilt_networks"`
			Authority    catalogAuthority `json:"authority"`
		}{change.WorkspaceID.String(), change.Session.ID().String(), saved.ID.String(), saved.Name, previousName,
			record.Tag.OwnerGroupIDs, record.Tag.OwnerRoles, len(networks), record.Authority}
		event.outboxClass = event.action
		event.outbox = struct {
			WorkspaceID string `json:"workspace_id"`
			TagID       string `json:"tag_id"`
			Version     int64  `json:"version"`
		}{change.WorkspaceID.String(), saved.ID.String(), saved.Version}
		if err := appendWorkspaceCatalogEvent(ctx, tx, change.WorkspaceID, event); err != nil {
			return false, errors.Join(devicetag.ErrUnavailable, err)
		}
		reason := struct {
			TagID string `json:"tag_id"`
			Name  string `json:"display_name"`
		}{saved.ID.String(), saved.Name}
		if err := appendNetworkWakeEvents(ctx, tx, networks, event, reason); err != nil {
			return false, errors.Join(devicetag.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return devicetag.Result{}, err
	}
	return result, nil
}

// NetworkOptions authorizes device.read and returns the tags the session may
// apply in the Network, the tags its Devices carry, and the Devices it owns.
func (store *DeviceTagStore) NetworkOptions(ctx context.Context, session accountsession.Session,
	scope network.Scope) (devicetag.NetworkOptions, error) {
	if !session.IsValid() || !scope.IsValid() {
		return devicetag.NetworkOptions{}, devicetag.ErrInvalid
	}
	var options devicetag.NetworkOptions
	err := store.transact(ctx, &scope, func(tx accountSessionTransaction, at time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readNetworkTagOptionsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), at)...).Scan(&encoded); err != nil {
			return false, deviceTagDatabaseError(err)
		}
		parsed, err := decodeNetworkTagOptions(encoded)
		options = parsed
		return false, err
	})
	if err != nil {
		return devicetag.NetworkOptions{}, err
	}
	return options, nil
}

func decodeNetworkTagOptions(encoded string) (devicetag.NetworkOptions, error) {
	var envelope struct {
		Tags []struct {
			TagID       string `json:"tag_id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Apply       string `json:"apply"`
		} `json:"tags"`
		OwnedDeviceIDs []string `json:"owned_device_ids"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil || envelope.Tags == nil ||
		envelope.OwnedDeviceIDs == nil || len(envelope.Tags) > devicetag.MaximumTags ||
		len(envelope.OwnedDeviceIDs) > devicetag.MaximumOwnedDevices {
		return devicetag.NetworkOptions{}, devicetag.ErrInvalid
	}
	options := devicetag.NetworkOptions{
		Tags:         make([]devicetag.TagOption, 0, len(envelope.Tags)),
		OwnedDevices: make([]node.ID, 0, len(envelope.OwnedDeviceIDs)),
	}
	for _, item := range envelope.Tags {
		id, err := devicetag.ParseID(item.TagID)
		apply := devicetag.Apply(item.Apply)
		if err != nil || !devicetag.ValidName(item.Name) ||
			(apply != devicetag.ApplyAnyDevice && apply != devicetag.ApplyOwnDevices && apply != devicetag.ApplyNone) {
			return devicetag.NetworkOptions{}, devicetag.ErrInvalid
		}
		options.Tags = append(options.Tags, devicetag.TagOption{
			ID: id, Name: item.Name, Description: item.Description, Apply: apply,
		})
	}
	for _, text := range envelope.OwnedDeviceIDs {
		device, err := node.ParseID(text)
		if err != nil {
			return devicetag.NetworkOptions{}, devicetag.ErrInvalid
		}
		options.OwnedDevices = append(options.OwnedDevices, device)
	}
	return options, nil
}

// NetworkTags authorizes device.read and returns the Network's tagged Devices.
func (store *DeviceTagStore) NetworkTags(ctx context.Context, session accountsession.Session,
	scope network.Scope) ([]devicetag.DeviceTags, error) {
	if !session.IsValid() || !scope.IsValid() {
		return nil, devicetag.ErrInvalid
	}
	var devices []devicetag.DeviceTags
	err := store.transact(ctx, &scope, func(tx accountSessionTransaction, at time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readNetworkDeviceTagsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), at)...).Scan(&encoded); err != nil {
			return false, deviceTagDatabaseError(err)
		}
		var envelope struct {
			Devices []struct {
				DeviceID string   `json:"device_id"`
				TagIDs   []string `json:"tag_ids"`
			} `json:"devices"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil || envelope.Devices == nil {
			return false, devicetag.ErrInvalid
		}
		devices = make([]devicetag.DeviceTags, 0, len(envelope.Devices))
		for _, item := range envelope.Devices {
			device, err := node.ParseID(item.DeviceID)
			if err != nil || len(item.TagIDs) == 0 || len(item.TagIDs) > devicetag.MaximumTags {
				return false, devicetag.ErrInvalid
			}
			tags, err := parseTagIDs(item.TagIDs)
			if err != nil {
				return false, err
			}
			devices = append(devices, devicetag.DeviceTags{DeviceID: device, Tags: tags})
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return devices, nil
}

func parseTagIDs(texts []string) ([]devicetag.ID, error) {
	tags := make([]devicetag.ID, 0, len(texts))
	for _, text := range texts {
		tag, err := devicetag.ParseID(text)
		if err != nil {
			return nil, devicetag.ErrInvalid
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// ChangeAssignments authorizes the tag change for one Device and commits it
// with evidence and the revision wakeup on the Network stream.
func (store *DeviceTagStore) ChangeAssignments(ctx context.Context, change devicetag.AssignmentChange) (
	devicetag.AssignmentResult, error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.DeviceID.IsValid() ||
		len(change.Add) != len(change.AddAssignmentIDs) || !change.CorrelationID.IsValid() {
		return devicetag.AssignmentResult{}, devicetag.ErrInvalid
	}
	type addition struct {
		TagID        string `json:"tag_id"`
		AssignmentID string `json:"assignment_id"`
	}
	additions := make([]addition, len(change.Add))
	added := make([]string, len(change.Add))
	for index, tag := range change.Add {
		additions[index] = addition{TagID: tag.String(), AssignmentID: change.AddAssignmentIDs[index].String()}
		added[index] = tag.String()
	}
	removed := make([]string, len(change.Remove))
	for index, tag := range change.Remove {
		removed[index] = tag.String()
	}
	addJSON, err := json.Marshal(additions)
	if err != nil {
		return devicetag.AssignmentResult{}, devicetag.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return devicetag.AssignmentResult{}, devicetag.ErrUnavailable
	}
	scope := change.Scope
	var result devicetag.AssignmentResult
	err = store.transact(ctx, &scope, func(tx accountSessionTransaction, at time.Time) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, changeDeviceTagsSQL, append(sessionQueryArguments(change.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), change.DeviceID.String(), addJSON, removed,
			changeID.String(), at)...).Scan(&encoded); err != nil {
			return false, deviceTagDatabaseError(err)
		}
		var record struct {
			DeviceID      string   `json:"device_id"`
			DeviceName    string   `json:"device_name"`
			TagIDs        []string `json:"tag_ids"`
			Added         int      `json:"added"`
			Removed       int      `json:"removed"`
			Changed       bool     `json:"changed"`
			HashBefore    string   `json:"tag_set_hash_before"`
			HashAfter     string   `json:"tag_set_hash_after"`
			Revision      int64    `json:"network_revision"`
			GroupRevision *int64   `json:"group_revision"`
			RoleBindingID *string  `json:"role_binding_id"`
			ManageAny     bool     `json:"manage_any"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.TagIDs == nil ||
			record.Changed != (record.Added+record.Removed > 0) || record.Revision <= 0 {
			return false, devicetag.ErrInvalid
		}
		device, err := node.ParseID(record.DeviceID)
		if err != nil || device != change.DeviceID {
			return false, devicetag.ErrInvalid
		}
		tags, err := parseTagIDs(record.TagIDs)
		if err != nil {
			return false, err
		}
		result = devicetag.AssignmentResult{DeviceID: device, DeviceName: record.DeviceName, Tags: tags,
			Added: record.Added, Removed: record.Removed, NetworkRevision: record.Revision}
		if !record.Changed {
			return false, nil
		}
		before, err := hex.DecodeString(record.HashBefore)
		if err != nil || len(before) != sha256.Size {
			return false, devicetag.ErrInvalid
		}
		after, err := hex.DecodeString(record.HashAfter)
		if err != nil || len(after) != sha256.Size || record.GroupRevision == nil {
			return false, devicetag.ErrInvalid
		}
		var beforeHash, afterHash [32]byte
		copy(beforeHash[:], before)
		copy(afterHash[:], after)
		permission := "device.read"
		if record.ManageAny {
			permission = "device_tag.manage"
		}
		binding := ""
		if record.RoleBindingID != nil {
			binding = *record.RoleBindingID
		}
		var streamID, sequence int64
		var previous []byte
		if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
			return false, errors.Join(devicetag.ErrUnavailable, err)
		}
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "device_tags", aggregateID: publicid.ID(device), version: record.Revision,
			networkVersion: record.Revision, action: "device.tags_changed", permission: permission,
			before: &beforeHash, after: afterHash,
			payload: struct {
				NetworkID     string   `json:"network_id"`
				SessionID     string   `json:"session_id"`
				RoleBindingID string   `json:"role_binding_id,omitempty"`
				DeviceID      string   `json:"device_id"`
				DeviceName    string   `json:"display_name"`
				AddedTags     []string `json:"added_tag_ids,omitempty"`
				RemovedTags   []string `json:"removed_tag_ids,omitempty"`
				TagSetBefore  string   `json:"tag_set_sha256_before"`
				TagSetAfter   string   `json:"tag_set_sha256"`
			}{scope.NetworkID().String(), change.Session.ID().String(), binding, device.String(), record.DeviceName,
				added, removed, record.HashBefore, record.HashAfter},
			outboxClass: "network.revision.advanced",
			outbox: struct {
				NetworkID       string `json:"network_id"`
				DeviceID        string `json:"device_id"`
				NetworkRevision int64  `json:"network_revision"`
				GroupRevision   int64  `json:"group_revision"`
			}{scope.NetworkID().String(), device.String(), record.Revision, *record.GroupRevision},
		}
		if err := appendCatalogEvent(ctx, tx, streamID, sequence, previous, event); err != nil {
			return false, errors.Join(devicetag.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return devicetag.AssignmentResult{}, err
	}
	return result, nil
}
