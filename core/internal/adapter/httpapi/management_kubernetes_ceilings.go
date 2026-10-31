package httpapi

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// parseCeilingHash reads a ceiling's hash from its path segment: 64
// lowercase hex digits, as the reads name it.
func parseCeilingHash(segment string) ([32]byte, bool) {
	var hash [32]byte
	if len(segment) != 64 {
		return hash, false
	}
	for index := range len(segment) {
		if character := segment[index]; (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return hash, false
		}
	}
	if _, err := hex.Decode(hash[:], []byte(segment)); err != nil {
		return hash, false
	}
	return hash, hash != [32]byte{}
}

type kubernetesCeilingBody struct {
	ContentHash string                     `json:"content_hash"`
	Truncated   bool                       `json:"truncated"`
	Groups      []kubecluster.CeilingGroup `json:"groups"`
}

func ceilingBodyOf(document kubecluster.CeilingDocument) kubernetesCeilingBody {
	return kubernetesCeilingBody{ContentHash: document.ContentHash, Truncated: document.Body.Truncated,
		Groups: document.Body.Groups}
}

// readKubernetesGroupCeilings answers a cluster's active replicas with their
// latest group ceilings and at most four distinct ceilings (K2h h4c), or
// one ceiling by its hash. A ceiling is what a gateway measured: a lower
// bound for people to read, never a decision.
func (handler *ManagementHandler) readKubernetesGroupCeilings(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string,
) string {
	manager := handler.kubernetesClusters
	if path.operation == kubernetesGroupCeilingReadOperation {
		document, err := manager.ReadGroupCeiling(ctx, session, path.scope, path.clusterID, path.contentHash)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, ceilingBodyOf(document))
		return "success"
	}
	ceilings, err := manager.ListGroupCeilings(ctx, session, path.scope, path.clusterID)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	type replicaBody struct {
		DeviceID    string  `json:"device_id"`
		ReceivedAt  *string `json:"received_at"`
		CheckedAt   *string `json:"checked_at"`
		ContentHash *string `json:"content_hash"`
		Stale       bool    `json:"stale"`
	}
	now := time.Now()
	replicas := make([]replicaBody, len(ceilings.Replicas))
	for index, replica := range ceilings.Replicas {
		body := replicaBody{DeviceID: replica.DeviceID.String()}
		if replica.ContentHash != "" {
			hash := replica.ContentHash
			body.ContentHash, body.ReceivedAt = &hash, optionalManagementTime(replica.ReceivedAt)
			body.CheckedAt = optionalManagementTime(replica.CheckedAt)
			body.Stale = now.Sub(replica.ReceivedAt) > kubecluster.CeilingStaleAfter
		}
		replicas[index] = body
	}
	bodies := make([]kubernetesCeilingBody, len(ceilings.Bodies))
	for index, document := range ceilings.Bodies {
		bodies[index] = ceilingBodyOf(document)
	}
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		Replicas          []replicaBody           `json:"replicas"`
		Ceilings          []kubernetesCeilingBody `json:"ceilings"`
		StaleAfterSeconds int64                   `json:"stale_after_seconds"`
	}{replicas, bodies, int64(kubecluster.CeilingStaleAfter / time.Second)})
	return "success"
}
