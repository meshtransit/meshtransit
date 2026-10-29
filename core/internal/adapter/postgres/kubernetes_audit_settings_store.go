package postgres

import (
	"context"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 250 (K1d d1d): a cluster's audit settings.
const (
	readKubernetesAuditSettingsSQL = `SELECT mesh_ops.read_kubernetes_audit_settings_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID)::TEXT`
	replaceKubernetesAuditSettingsSQL = `SELECT mesh_ops.replace_kubernetes_audit_settings_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::BIGINT,$14::TEXT[],$15::TEXT[],$16::UUID)::TEXT`
	auditSettingsReplacedAction = "kubernetes_cluster.audit_settings_replaced"
)

// auditSettingsExportAuthority is what granted audit.export for a change of
// the settings, beside what granted manage: a role binding, or the
// Workspace's ownership (no binding, an owner generation).
type auditSettingsExportAuthority struct {
	catalogAuthority
	Scope string `json:"scope"`
}

func (authority auditSettingsExportAuthority) valid() bool {
	if authority.Scope != "workspace" && authority.Scope != "network" {
		return false
	}
	if authority.BindingID == "" && authority.RoleID == "" {
		return authority.OwnerGeneration > 0
	}
	_, bindingErr := publicid.Parse(authority.BindingID)
	_, roleErr := publicid.Parse(authority.RoleID)
	return bindingErr == nil && roleErr == nil
}

type kubernetesAuditSettingsDocument struct {
	PrivilegedGroups []string   `json:"privileged_groups"`
	SecretResources  []string   `json:"secret_resources"`
	Version          int64      `json:"version"`
	UpdatedAt        *time.Time `json:"updated_at"`
}

func (document kubernetesAuditSettingsDocument) settings() (kubecluster.AuditSettings, error) {
	if document.PrivilegedGroups == nil || document.SecretResources == nil || document.Version < 0 ||
		(document.Version == 0) != (document.UpdatedAt == nil) ||
		len(document.PrivilegedGroups) > kubecluster.MaximumAuditSettingsEntries ||
		len(document.SecretResources) > kubecluster.MaximumAuditSettingsEntries {
		return kubecluster.AuditSettings{}, kubecluster.ErrInvalid
	}
	settings := kubecluster.AuditSettings{PrivilegedGroups: document.PrivilegedGroups,
		SecretResources: document.SecretResources, Version: document.Version}
	if document.UpdatedAt != nil {
		settings.UpdatedAt = document.UpdatedAt.UTC()
	}
	return settings, nil
}

// ReadAuditSettings reads a cluster's audit settings.
func (store *KubernetesClusterStore) ReadAuditSettings(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID) (kubecluster.AuditSettings, error) {
	var settings kubecluster.AuditSettings
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesAuditSettingsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String())...).Scan(
			&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var document kubernetesAuditSettingsDocument
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

// ReplaceAuditSettings replaces a cluster's audit settings and records
// kubernetes_cluster.audit_settings_replaced on the Network's stream.
func (store *KubernetesClusterStore) ReplaceAuditSettings(ctx context.Context,
	replacement kubecluster.AuditSettingsReplacement) (kubecluster.AuditSettingsResult, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.AuditSettingsResult{}, kubecluster.ErrUnavailable
	}
	scope := replacement.Scope
	var result kubecluster.AuditSettingsResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, replaceKubernetesAuditSettingsSQL, append(sessionQueryArguments(replacement.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), replacement.ClusterID.String(),
			replacement.ExpectedVersion, replacement.PrivilegedGroups, replacement.SecretResources,
			changeID.String())...).Scan(
			&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record struct {
			NetworkID       string                           `json:"network_id"`
			NetworkRevision *int64                           `json:"network_revision"`
			ClusterID       string                           `json:"cluster_id"`
			Changed         bool                             `json:"changed"`
			Before          *kubernetesAuditSettingsDocument `json:"before"`
			Settings        kubernetesAuditSettingsDocument  `json:"settings"`
			Authority       *catalogAuthority                `json:"authority"`
			ExportAuthority *auditSettingsExportAuthority    `json:"export_authority"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.ClusterID != replacement.ClusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		settings, err := record.Settings.settings()
		if err != nil || !slices.Equal(settings.PrivilegedGroups, replacement.PrivilegedGroups) ||
			!slices.Equal(settings.SecretResources, replacement.SecretResources) {
			return false, kubecluster.ErrInvalid
		}
		result = kubecluster.AuditSettingsResult{Settings: settings, Changed: record.Changed}
		if !record.Changed {
			return false, nil
		}
		if record.NetworkRevision == nil || *record.NetworkRevision < 1 || record.Authority == nil ||
			record.ExportAuthority == nil || !record.ExportAuthority.valid() ||
			settings.Version != replacement.ExpectedVersion+1 || (record.Before == nil) != (settings.Version == 1) {
			return false, kubecluster.ErrInvalid
		}
		return true, store.appendAuditSettingsEvent(ctx, tx, replacement, changeID, *record.NetworkRevision,
			*record.Authority, *record.ExportAuthority, record.Before, settings)
	})
	return result, err
}

func (store *KubernetesClusterStore) appendAuditSettingsEvent(ctx context.Context, tx accountSessionTransaction,
	replacement kubecluster.AuditSettingsReplacement, changeID publicid.ID, networkRevision int64,
	authority catalogAuthority, exportAuthority auditSettingsExportAuthority, before *kubernetesAuditSettingsDocument,
	settings kubecluster.AuditSettings) error {
	type audited struct {
		NetworkID        string   `json:"network_id"`
		ClusterID        string   `json:"cluster_id"`
		Version          int64    `json:"version"`
		PrivilegedGroups []string `json:"privileged_groups"`
		SecretResources  []string `json:"secret_resources"`
	}
	networkID, clusterID := replacement.Scope.NetworkID().String(), replacement.ClusterID.String()
	after := audited{networkID, clusterID, settings.Version, settings.PrivilegedGroups, settings.SecretResources}
	afterHash, err := kubernetesSemanticHash(after)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: replacement.Session, correlationID: replacement.CorrelationID, changeID: changeID,
		aggregateKind: "kubernetes_cluster_audit_settings", aggregateID: publicid.ID(replacement.ClusterID),
		version: settings.Version, networkVersion: networkRevision, action: auditSettingsReplacedAction,
		permission: "kubernetes_cluster.manage", after: afterHash, outboxClass: auditSettingsReplacedAction,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			Version   int64  `json:"version"`
		}{networkID, clusterID, settings.Version},
	}
	var previous *audited
	if before != nil {
		previous = &audited{networkID, clusterID, before.Version, before.PrivilegedGroups, before.SecretResources}
		beforeHash, err := kubernetesSemanticHash(*previous)
		if err != nil {
			return kubecluster.ErrInvalid
		}
		event.before = &beforeHash
	}
	event.payload = struct {
		NetworkID       string                       `json:"network_id"`
		SessionID       string                       `json:"session_id"`
		ClusterID       string                       `json:"cluster_id"`
		Before          *audited                     `json:"before"`
		After           audited                      `json:"after"`
		Authority       catalogAuthority             `json:"authority"`
		ExportAuthority auditSettingsExportAuthority `json:"export_authority"`
	}{networkID, replacement.Session.ID().String(), clusterID, previous, after, authority, exportAuthority}
	return appendNetworkMemberEvent(ctx, tx, event)
}
