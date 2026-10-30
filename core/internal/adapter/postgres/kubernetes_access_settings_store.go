package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 262 (K2d d4b): a cluster's access settings.
const (
	readKubernetesAccessSettingsSQL = `SELECT mesh_ops.read_kubernetes_access_settings_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID)::TEXT`
	replaceKubernetesAccessSettingsSQL = `SELECT mesh_ops.replace_kubernetes_access_settings_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::BIGINT,$14::TEXT,$15::UUID)::TEXT`
	accessSettingsReplacedAction = "kubernetes_cluster.access_settings_replaced"
)

type kubernetesAccessSettingsDocument struct {
	AccessContact *string    `json:"access_contact"`
	Version       int64      `json:"version"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

func (document kubernetesAccessSettingsDocument) settings() (kubecluster.AccessSettings, error) {
	if document.AccessContact == nil || !kubecluster.ValidAccessContact(*document.AccessContact) ||
		document.Version < 0 || (document.Version == 0) != (document.UpdatedAt == nil) {
		return kubecluster.AccessSettings{}, kubecluster.ErrInvalid
	}
	settings := kubecluster.AccessSettings{AccessContact: *document.AccessContact, Version: document.Version}
	if document.UpdatedAt != nil {
		settings.UpdatedAt = document.UpdatedAt.UTC()
	}
	return settings, nil
}

// ReadAccessSettings reads a cluster's access settings.
func (store *KubernetesClusterStore) ReadAccessSettings(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID) (kubecluster.AccessSettings, error) {
	var settings kubecluster.AccessSettings
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesAccessSettingsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String())...).Scan(
			&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var document kubernetesAccessSettingsDocument
		if err := decodeIdentityCatalogJSON([]byte(encoded), &document); err != nil {
			return false, kubecluster.ErrInvalid
		}
		read, err := document.settings()
		if err != nil {
			return false, err
		}
		settings = read
		return false, nil
	})
	return settings, err
}

// ReplaceAccessSettings replaces a cluster's access contact, advancing the
// Network revision so its gateways' maps carry it, and records
// kubernetes_cluster.access_settings_replaced on the Network's stream.
func (store *KubernetesClusterStore) ReplaceAccessSettings(ctx context.Context,
	replacement kubecluster.AccessSettingsReplacement) (kubecluster.AccessSettingsResult, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.AccessSettingsResult{}, kubecluster.ErrUnavailable
	}
	scope := replacement.Scope
	var result kubecluster.AccessSettingsResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, replaceKubernetesAccessSettingsSQL, append(
			sessionQueryArguments(replacement.Session), scope.WorkspaceID().String(), scope.NetworkID().String(),
			replacement.ClusterID.String(), replacement.ExpectedVersion, replacement.AccessContact,
			changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record struct {
			NetworkID       string                            `json:"network_id"`
			NetworkRevision *int64                            `json:"network_revision"`
			ClusterID       string                            `json:"cluster_id"`
			Changed         bool                              `json:"changed"`
			Before          *kubernetesAccessSettingsDocument `json:"before"`
			Settings        kubernetesAccessSettingsDocument  `json:"settings"`
			Authority       *catalogAuthority                 `json:"authority"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.ClusterID != replacement.ClusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		settings, err := record.Settings.settings()
		if err != nil || settings.AccessContact != replacement.AccessContact && record.Changed {
			return false, kubecluster.ErrInvalid
		}
		result = kubecluster.AccessSettingsResult{Settings: settings, Changed: record.Changed}
		if !record.Changed {
			return false, nil
		}
		if record.NetworkRevision == nil || *record.NetworkRevision < 1 || record.Authority == nil ||
			settings.Version != replacement.ExpectedVersion+1 || (record.Before == nil) != (settings.Version == 1) {
			return false, kubecluster.ErrInvalid
		}
		return true, store.appendAccessSettingsEvent(ctx, tx, replacement, changeID, *record.NetworkRevision,
			*record.Authority, record.Before, settings)
	})
	return result, err
}

func (store *KubernetesClusterStore) appendAccessSettingsEvent(ctx context.Context, tx accountSessionTransaction,
	replacement kubecluster.AccessSettingsReplacement, changeID publicid.ID, networkRevision int64,
	authority catalogAuthority, before *kubernetesAccessSettingsDocument, settings kubecluster.AccessSettings) error {
	type audited struct {
		NetworkID     string `json:"network_id"`
		ClusterID     string `json:"cluster_id"`
		Version       int64  `json:"version"`
		AccessContact string `json:"access_contact"`
	}
	networkID, clusterID := replacement.Scope.NetworkID().String(), replacement.ClusterID.String()
	after := audited{networkID, clusterID, settings.Version, settings.AccessContact}
	afterHash, err := kubernetesSemanticHash(after)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	// The Network's revision advanced: map sessions read it (DNS settings
	// announce theirs alike).
	event := catalogEvent{
		session: replacement.Session, correlationID: replacement.CorrelationID, changeID: changeID,
		aggregateKind: "kubernetes_cluster_access_settings", aggregateID: publicid.ID(replacement.ClusterID),
		version: settings.Version, networkVersion: networkRevision, action: accessSettingsReplacedAction,
		permission: "kubernetes_cluster.manage", after: afterHash, outboxClass: "network.revision.advanced",
		outbox: struct {
			NetworkID       string `json:"network_id"`
			ClusterID       string `json:"cluster_id"`
			Version         int64  `json:"version"`
			NetworkRevision int64  `json:"network_revision"`
		}{networkID, clusterID, settings.Version, networkRevision},
	}
	var previous *audited
	if before != nil && before.AccessContact != nil {
		previous = &audited{networkID, clusterID, before.Version, *before.AccessContact}
		beforeHash, err := kubernetesSemanticHash(*previous)
		if err != nil {
			return kubecluster.ErrInvalid
		}
		event.before = &beforeHash
	}
	event.payload = struct {
		NetworkID string           `json:"network_id"`
		SessionID string           `json:"session_id"`
		ClusterID string           `json:"cluster_id"`
		Before    *audited         `json:"before"`
		After     audited          `json:"after"`
		Authority catalogAuthority `json:"authority"`
	}{networkID, replacement.Session.ID().String(), clusterID, previous, after, authority}
	return appendNetworkMemberEvent(ctx, tx, event)
}
