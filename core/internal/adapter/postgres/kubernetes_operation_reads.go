package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 249 (K1d d1c): a cluster's operations and denials for audit
// readers.
const (
	listKubernetesOperationsSQL = `SELECT mesh_ops.list_kubernetes_operations_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::TIMESTAMPTZ,$15::TIMESTAMPTZ,$16::UUID,$17::TEXT,$18::UUID,
 $19::TEXT,$20::INTEGER,$21::INTEGER)::TEXT`
	readKubernetesOperationSQL = `SELECT mesh_ops.read_kubernetes_operation_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID)::TEXT`
	countKubernetesDenialsSQL = `SELECT mesh_ops.kubernetes_operation_denial_counts_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::TIMESTAMPTZ)::TEXT`
)

type kubernetesOperationDocument struct {
	AuditID         string    `json:"audit_id"`
	ReceivedAt      time.Time `json:"received_at"`
	Class           string    `json:"class"`
	Groups          []string  `json:"groups"`
	Verb            string    `json:"verb"`
	APIGroup        string    `json:"api_group"`
	Resource        string    `json:"resource"`
	Subresource     string    `json:"subresource"`
	Namespace       string    `json:"namespace"`
	Name            string    `json:"name"`
	Impersonated    string    `json:"impersonated"`
	OwnerKind       string    `json:"owner_kind"`
	OwnerRef        string    `json:"owner_ref"`
	NetworkRevision int64     `json:"network_revision"`
	ClockSkew       bool      `json:"clock_skew"`
	GatewayDeviceID *string   `json:"gateway_device_id"`
	PeerDeviceID    *string   `json:"peer_device_id"`
	Status          *int      `json:"status"`
	DurationMS      *int      `json:"duration_ms"`
}

func (document kubernetesOperationDocument) operation() (kubecluster.Operation, error) {
	invalid := kubecluster.ErrInvalid
	auditID, err := publicid.Parse(document.AuditID)
	if err != nil || !auditID.IsValid() || document.ReceivedAt.IsZero() || document.Verb == "" ||
		document.Groups == nil || document.NetworkRevision < 1 {
		return kubecluster.Operation{}, invalid
	}
	operation := kubecluster.Operation{AuditID: auditID, ReceivedAt: document.ReceivedAt.UTC(),
		Class: document.Class, Groups: document.Groups, Verb: document.Verb, APIGroup: document.APIGroup,
		Resource: document.Resource, Subresource: document.Subresource, Namespace: document.Namespace,
		Name: document.Name, Impersonated: document.Impersonated, OwnerKind: document.OwnerKind,
		OwnerRef: document.OwnerRef, NetworkRevision: document.NetworkRevision, ClockSkew: document.ClockSkew}
	for _, pair := range []struct {
		from *string
		to   *node.ID
	}{{document.GatewayDeviceID, &operation.GatewayDeviceID}, {document.PeerDeviceID, &operation.PeerDeviceID}} {
		if pair.from == nil {
			continue
		}
		if *pair.to, err = node.ParseID(*pair.from); err != nil {
			return kubecluster.Operation{}, invalid
		}
	}
	if (document.Status == nil) != (document.DurationMS == nil) {
		return kubecluster.Operation{}, invalid
	}
	if document.Status != nil {
		operation.HasOutcome, operation.Status, operation.DurationMS = true, *document.Status, *document.DurationMS
	}
	return operation, nil
}

// ListOperations reads a page of a cluster's operations with a bounded scan.
func (store *KubernetesClusterStore) ListOperations(ctx context.Context,
	query kubecluster.OperationQuery) (kubecluster.OperationPage, error) {
	var afterAt *time.Time
	var afterID, ownerRef, peer, class *string
	if !query.After.IsZero() {
		at, id := query.After.At.UTC(), query.After.ID.String()
		afterAt, afterID = &at, &id
	}
	if query.OwnerRef != "" {
		ownerRef = &query.OwnerRef
	}
	if query.PeerDeviceID.IsValid() {
		id := query.PeerDeviceID.String()
		peer = &id
	}
	if query.Class != "" {
		class = &query.Class
	}
	var read struct {
		Operations    []kubernetesOperationDocument `json:"operations"`
		Truncated     bool                          `json:"truncated"`
		LastScannedAt *time.Time                    `json:"last_scanned_at"`
		LastScannedID *string                       `json:"last_scanned_id"`
	}
	err := store.transact(ctx, query.Scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listKubernetesOperationsSQL, append(sessionQueryArguments(query.Session),
			query.Scope.WorkspaceID().String(), query.Scope.NetworkID().String(), query.ClusterID.String(),
			query.From.UTC(), query.To.UTC(), afterAt, afterID, ownerRef, peer, class, query.Limit,
			query.ScanBudget)...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil {
			return false, kubecluster.ErrInvalid
		}
		return false, nil
	})
	if err != nil {
		return kubecluster.OperationPage{}, err
	}
	if read.Operations == nil || len(read.Operations) > query.Limit+1 || read.Truncated && len(read.Operations) > query.Limit {
		return kubecluster.OperationPage{}, kubecluster.ErrInvalid
	}
	page := kubecluster.OperationPage{
		Operations: make([]kubecluster.Operation, 0, min(len(read.Operations), query.Limit)), Truncated: read.Truncated,
	}
	previous := query.After
	for _, document := range read.Operations[:min(len(read.Operations), query.Limit)] {
		operation, err := document.operation()
		if err != nil {
			return kubecluster.OperationPage{}, err
		}
		if operation.ReceivedAt.Before(query.From) || !operation.ReceivedAt.Before(query.To) ||
			!beforeCursor(previous, operation.ReceivedAt, operation.AuditID) ||
			query.Class != "" && operation.Class != query.Class ||
			query.OwnerRef != "" && operation.OwnerRef != query.OwnerRef ||
			query.PeerDeviceID.IsValid() && operation.PeerDeviceID != query.PeerDeviceID {
			return kubecluster.OperationPage{}, kubecluster.ErrInvalid
		}
		previous = kubecluster.PageCursor{At: operation.ReceivedAt, ID: operation.AuditID}
		page.Operations = append(page.Operations, operation)
	}
	switch {
	case len(read.Operations) > query.Limit:
		page.Next = previous
	case read.Truncated:
		if read.LastScannedAt == nil || read.LastScannedID == nil {
			return kubecluster.OperationPage{}, kubecluster.ErrInvalid
		}
		// The last row scanned may be the last kept (review d1c H1).
		id, err := publicid.Parse(*read.LastScannedID)
		scanned := kubecluster.PageCursor{At: read.LastScannedAt.UTC(), ID: id}
		if err != nil || !(scanned.At.Equal(previous.At) && scanned.ID == previous.ID) &&
			!beforeCursor(previous, scanned.At, scanned.ID) {
			return kubecluster.OperationPage{}, kubecluster.ErrInvalid
		}
		page.Next = kubecluster.PageCursor{At: read.LastScannedAt.UTC(), ID: id}
	}
	return page, nil
}

// ReadOperation reads one of a cluster's operations by its audit ID.
func (store *KubernetesClusterStore) ReadOperation(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, auditID publicid.ID) (kubecluster.Operation, error) {
	var operation kubecluster.Operation
	err := store.readOne(ctx, readKubernetesOperationSQL, session, scope, clusterID, auditID.String(),
		func(encoded []byte) error {
			var document kubernetesOperationDocument
			if err := decodeIdentityCatalogJSON(encoded, &document); err != nil {
				return kubecluster.ErrInvalid
			}
			read, err := document.operation()
			if err != nil || read.AuditID != auditID {
				return kubecluster.ErrInvalid
			}
			operation = read
			return nil
		})
	return operation, err
}

// CountDenials sums a cluster's denials in [from, to) by reason.
func (store *KubernetesClusterStore) CountDenials(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, from, to time.Time) (kubecluster.DenialSums, error) {
	var read struct {
		Counts []struct {
			Reason  string    `json:"reason"`
			Count   int64     `json:"count"`
			FirstAt time.Time `json:"first_at"`
			LastAt  time.Time `json:"last_at"`
		} `json:"counts"`
		Truncated   bool       `json:"truncated"`
		CountedFrom *time.Time `json:"counted_from"`
	}
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, countKubernetesDenialsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String(), from.UTC(),
			to.UTC())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil {
			return false, kubecluster.ErrInvalid
		}
		return false, nil
	})
	if err != nil {
		return kubecluster.DenialSums{}, err
	}
	if read.Counts == nil || len(read.Counts) > 16 || read.Truncated && read.CountedFrom == nil {
		return kubecluster.DenialSums{}, kubecluster.ErrInvalid
	}
	sums := kubecluster.DenialSums{Counts: make([]kubecluster.DenialCount, 0, len(read.Counts)),
		Truncated: read.Truncated}
	if read.CountedFrom != nil {
		sums.CountedFrom = read.CountedFrom.UTC()
	}
	for _, document := range read.Counts {
		if document.Reason == "" || document.Count < 1 || document.LastAt.Before(document.FirstAt) {
			return kubecluster.DenialSums{}, kubecluster.ErrInvalid
		}
		sums.Counts = append(sums.Counts, kubecluster.DenialCount{Reason: document.Reason, Count: document.Count,
			FirstAt: document.FirstAt.UTC(), LastAt: document.LastAt.UTC()})
	}
	return sums, nil
}
