package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 251 (K1d d1d-b): a cluster's operations exported for meshctl kube
// audit-check, one short transaction a page.
const (
	beginKubernetesOperationExportSQL = `SELECT mesh_ops.begin_kubernetes_operation_export_v1(` + sessionArguments +
		`,$10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::TIMESTAMPTZ)::TEXT`
	listKubernetesOperationExportSQL = `SELECT mesh_ops.list_kubernetes_operation_export_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::TIMESTAMPTZ,$15::TIMESTAMPTZ,$16::UUID,$17::INTEGER)::TEXT`
)

// BeginExport reads an export's header and bounded count.
func (store *KubernetesClusterStore) BeginExport(ctx context.Context,
	query kubecluster.ExportQuery) (kubecluster.ExportHeader, error) {
	from, to := query.RecordsRange()
	var read struct {
		ClusterID        string                          `json:"cluster_id"`
		GatewayNamespace *string                         `json:"gateway_namespace"`
		Settings         kubernetesAuditSettingsDocument `json:"settings"`
		Count            int                             `json:"count"`
	}
	err := store.transact(ctx, query.Scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, beginKubernetesOperationExportSQL, append(sessionQueryArguments(query.Session),
			query.Scope.WorkspaceID().String(), query.Scope.NetworkID().String(), query.ClusterID.String(),
			from.UTC(), to.UTC())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil {
			return false, kubecluster.ErrInvalid
		}
		return false, nil
	})
	if err != nil {
		return kubecluster.ExportHeader{}, err
	}
	settings, err := read.Settings.settings()
	if err != nil || read.ClusterID != query.ClusterID.String() || read.Count < 0 ||
		read.Count > kubecluster.MaximumExportRecords+1 {
		return kubecluster.ExportHeader{}, kubecluster.ErrInvalid
	}
	header := kubecluster.ExportHeader{ClusterID: query.ClusterID, Settings: settings, Count: read.Count}
	if read.GatewayNamespace != nil {
		header.GatewayNamespace = *read.GatewayNamespace
	}
	return header, nil
}

// ExportPage reads the records after after, oldest first.
func (store *KubernetesClusterStore) ExportPage(ctx context.Context, query kubecluster.ExportQuery,
	after kubecluster.PageCursor) ([]kubecluster.ExportRecord, error) {
	from, to := query.RecordsRange()
	var afterAt *time.Time
	var afterID *string
	if !after.IsZero() {
		at, id := after.At.UTC(), after.ID.String()
		afterAt, afterID = &at, &id
	}
	var documents []struct {
		AuditID      string    `json:"audit_id"`
		ReceivedAt   time.Time `json:"received_at"`
		Class        string    `json:"class"`
		Groups       []string  `json:"groups"`
		Verb         string    `json:"verb"`
		APIGroup     string    `json:"api_group"`
		Resource     string    `json:"resource"`
		Subresource  string    `json:"subresource"`
		Namespace    string    `json:"namespace"`
		Name         string    `json:"name"`
		Impersonated string    `json:"impersonated"`
		Status       int       `json:"status"`
	}
	err := store.transact(ctx, query.Scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listKubernetesOperationExportSQL, append(sessionQueryArguments(query.Session),
			query.Scope.WorkspaceID().String(), query.Scope.NetworkID().String(), query.ClusterID.String(),
			from.UTC(), to.UTC(), afterAt, afterID, kubecluster.ExportPageSize)...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &documents); err != nil {
			return false, kubecluster.ErrInvalid
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if documents == nil || len(documents) > kubecluster.ExportPageSize {
		return nil, kubecluster.ErrInvalid
	}
	records := make([]kubecluster.ExportRecord, 0, len(documents))
	previous := after
	for _, document := range documents {
		id, err := publicid.Parse(document.AuditID)
		at := document.ReceivedAt.UTC()
		// Oldest first: each record is after the one before.
		if err != nil || !id.IsValid() || at.Before(from) || !at.Before(to) || document.Groups == nil ||
			!previous.IsZero() && !beforeCursor(kubecluster.PageCursor{At: at, ID: id}, previous.At, previous.ID) {
			return nil, kubecluster.ErrInvalid
		}
		previous = kubecluster.PageCursor{At: at, ID: id}
		records = append(records, kubecluster.ExportRecord{AuditID: id, ReceivedAt: at, Class: document.Class,
			Groups: document.Groups, Verb: document.Verb, APIGroup: document.APIGroup, Resource: document.Resource,
			Subresource: document.Subresource, Namespace: document.Namespace, Name: document.Name,
			Impersonated: document.Impersonated, Status: document.Status})
	}
	return records, nil
}
