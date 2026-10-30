package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 252 (K1d d2a): requests to retire a cluster's CA, recorded by the
// API and carried out by the CA worker.
const (
	requestKubernetesCARetireSQL = `SELECT mesh_ops.request_kubernetes_ca_retire_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::BIGINT,$15::TEXT,$16::TEXT,$17::TEXT,$18::UUID)::TEXT`
	listKubernetesCARetireRequestsSQL = `SELECT mesh_ops.list_kubernetes_ca_retire_requests_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::UUID,$15::INTEGER)::TEXT`
	caRetireRequestedAction        = "kubernetes_cluster.ca_retire_requested"
	kubernetesClusterCanApproveSQL = `SELECT mesh_ops.kubernetes_cluster_can_approve_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID)`
)

type kubernetesCARetireRequestDocument struct {
	RequestID   string     `json:"request_id"`
	CAID        string     `json:"ca_id"`
	CAVersion   int64      `json:"ca_version"`
	Reason      string     `json:"reason"`
	ChangeRef   string     `json:"change_ref"`
	Note        string     `json:"note"`
	RequestedBy *string    `json:"requested_by_principal_id"`
	State       string     `json:"state"`
	Refusal     *string    `json:"refusal"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	FinishedAt  *time.Time `json:"finished_at"`
}

func (document kubernetesCARetireRequestDocument) request() (kubecluster.CARetireRequest, error) {
	id, idErr := publicid.Parse(document.RequestID)
	caID, caErr := publicid.Parse(document.CAID)
	request := kubecluster.CARetireRequest{ID: id, CAID: caID, CAVersion: document.CAVersion,
		Reason: document.Reason, ChangeRef: document.ChangeRef, Note: document.Note, State: document.State,
		CreatedAt: document.CreatedAt.UTC(), ExpiresAt: document.ExpiresAt.UTC()}
	if document.RequestedBy != nil {
		by, err := publicid.Parse(*document.RequestedBy)
		if err != nil {
			return kubecluster.CARetireRequest{}, kubecluster.ErrInvalid
		}
		request.RequestedBy = by
	}
	if document.Refusal != nil {
		request.Refusal = *document.Refusal
	}
	if document.FinishedAt != nil {
		request.FinishedAt = document.FinishedAt.UTC()
	}
	pending := request.State == kubecluster.RetireStatePending
	refused := request.State == kubecluster.RetireStateRefused
	known := pending || refused || request.State == kubecluster.RetireStateDone
	if idErr != nil || caErr != nil || !id.IsValid() || !caID.IsValid() || request.CAVersion < 1 || !known ||
		!kubecluster.ValidRetireReason(request.Reason) || request.ChangeRef == "" ||
		!request.ExpiresAt.Equal(request.CreatedAt.Add(kubecluster.RetireRequestLifetime)) ||
		pending != request.FinishedAt.IsZero() || refused != (request.Refusal != "") ||
		!pending && request.FinishedAt.Before(request.CreatedAt) {
		return kubecluster.CARetireRequest{}, kubecluster.ErrInvalid
	}
	return request, nil
}

// RequestCARetire records a request to retire a CA with its evidence, or
// returns the one already waiting for the same CA and reason.
func (store *KubernetesClusterStore) RequestCARetire(ctx context.Context,
	command kubecluster.CARetireRequestCommand) (kubecluster.CARetireRequestResult, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.CARetireRequestResult{}, kubecluster.ErrUnavailable
	}
	scope := command.Scope
	var result kubecluster.CARetireRequestResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, requestKubernetesCARetireSQL, append(sessionQueryArguments(command.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), command.ClusterID.String(),
			command.CAID.String(), command.CAVersion, command.Reason, command.ChangeRef, command.Note,
			changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record struct {
			NetworkID       string                            `json:"network_id"`
			NetworkRevision *int64                            `json:"network_revision"`
			ClusterID       string                            `json:"cluster_id"`
			Created         bool                              `json:"created"`
			Request         kubernetesCARetireRequestDocument `json:"request"`
			Authority       *catalogAuthority                 `json:"authority"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.ClusterID != command.ClusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		request, err := record.Request.request()
		if err != nil || request.CAID != command.CAID || request.Reason != command.Reason {
			return false, kubecluster.ErrInvalid
		}
		result = kubecluster.CARetireRequestResult{Request: request, Created: record.Created}
		if !record.Created {
			return false, nil
		}
		if record.NetworkRevision == nil || *record.NetworkRevision < 1 || record.Authority == nil ||
			request.State != kubecluster.RetireStatePending || request.CAVersion != command.CAVersion ||
			request.ChangeRef != command.ChangeRef || request.Note != command.Note {
			return false, kubecluster.ErrInvalid
		}
		return true, store.appendCARetireRequestedEvent(ctx, tx, command, changeID, *record.NetworkRevision,
			*record.Authority, request)
	})
	return result, err
}

func (store *KubernetesClusterStore) appendCARetireRequestedEvent(ctx context.Context,
	tx accountSessionTransaction, command kubecluster.CARetireRequestCommand, changeID publicid.ID,
	networkRevision int64, authority catalogAuthority, request kubecluster.CARetireRequest) error {
	type audited struct {
		NetworkID string `json:"network_id"`
		ClusterID string `json:"cluster_id"`
		RequestID string `json:"request_id"`
		CAID      string `json:"ca_id"`
		CAVersion int64  `json:"ca_version"`
		Reason    string `json:"reason"`
		ChangeRef string `json:"change_ref"`
		Note      string `json:"note"`
	}
	networkID, clusterID := command.Scope.NetworkID().String(), command.ClusterID.String()
	after := audited{networkID, clusterID, request.ID.String(), request.CAID.String(), request.CAVersion,
		request.Reason, request.ChangeRef, request.Note}
	afterHash, err := kubernetesSemanticHash(after)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: command.Session, correlationID: command.CorrelationID, changeID: changeID,
		aggregateKind: "kubernetes_ca_retire_request", aggregateID: request.ID,
		version: 1, networkVersion: networkRevision, action: caRetireRequestedAction,
		permission: "kubernetes_cluster.approve", after: afterHash, outboxClass: caRetireRequestedAction,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			RequestID string `json:"request_id"`
			CAID      string `json:"ca_id"`
			Reason    string `json:"reason"`
		}{networkID, clusterID, request.ID.String(), request.CAID.String(), request.Reason},
	}
	event.payload = struct {
		NetworkID string           `json:"network_id"`
		SessionID string           `json:"session_id"`
		ClusterID string           `json:"cluster_id"`
		After     audited          `json:"after"`
		Authority catalogAuthority `json:"authority"`
	}{networkID, command.Session.ID().String(), clusterID, after, authority}
	return appendNetworkMemberEvent(ctx, tx, event)
}

// ListCARetireRequests reads a page of a cluster's requests, newest first.
func (store *KubernetesClusterStore) ListCARetireRequests(ctx context.Context,
	query kubecluster.PageQuery) (kubecluster.CARetireRequestPage, error) {
	var documents []kubernetesCARetireRequestDocument
	if err := store.readPage(ctx, listKubernetesCARetireRequestsSQL, query, &documents); err != nil {
		return kubecluster.CARetireRequestPage{}, err
	}
	if documents == nil || len(documents) > query.Limit+1 {
		return kubecluster.CARetireRequestPage{}, kubecluster.ErrInvalid
	}
	page := kubecluster.CARetireRequestPage{
		Requests: make([]kubecluster.CARetireRequest, 0, min(len(documents), query.Limit))}
	previous := query.After
	for _, document := range documents[:min(len(documents), query.Limit)] {
		request, err := document.request()
		if err != nil || !beforeCursor(previous, request.CreatedAt, request.ID) {
			return kubecluster.CARetireRequestPage{}, kubecluster.ErrInvalid
		}
		previous = kubecluster.PageCursor{At: request.CreatedAt, ID: request.ID}
		page.Requests = append(page.Requests, request)
	}
	if len(documents) > query.Limit {
		page.Next = previous
	}
	return page, nil
}
