package rebalance

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ScalePath is the operator route an autoscaler polls (KEDA metrics-api).
const ScalePath = "/scale/v1/sessions"

// scaleReadTimeout bounds one registry read for the autoscaler.
const scaleReadTimeout = 2 * time.Second

// LoadReader reads every live replica's load.
type LoadReader interface {
	Loads(ctx context.Context) ([]ReplicaLoad, error)
}

type scaleResponse struct {
	// Sessions is the control sessions of every live replica; an autoscaler
	// divides it by a target per replica.
	Sessions int `json:"sessions"`
	Replicas int `json:"replicas"`
}

// ScaleHandler answers the cluster's control session total. It reveals no
// identifier, only two counts, and is served on the operator listener.
func ScaleHandler(reader LoadReader) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), scaleReadTimeout)
		defer cancel()
		loads, err := reader.Loads(ctx)
		response.Header().Set("Cache-Control", "no-store")
		if err != nil {
			http.Error(response, "load registry unavailable", http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(scaleResponse{Sessions: Total(loads), Replicas: len(loads)})
	})
}
