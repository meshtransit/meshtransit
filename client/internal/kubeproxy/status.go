package kubeproxy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// status is a Kubernetes Status, what kubectl shows of a refusal.
type status struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   struct{}          `json:"metadata"`
	Status     string            `json:"status"`
	Message    string            `json:"message"`
	Reason     string            `json:"reason"`
	Code       int               `json:"code"`
	Details    map[string]string `json:"details,omitempty"`
}

// reasons are the Status reasons of the codes the gateway answers.
var reasons = map[int]string{
	http.StatusBadRequest: "BadRequest", http.StatusForbidden: "Forbidden", http.StatusNotFound: "NotFound",
	http.StatusMethodNotAllowed: "MethodNotAllowed", http.StatusRequestEntityTooLarge: "RequestEntityTooLarge",
	http.StatusTooManyRequests: "TooManyRequests", http.StatusServiceUnavailable: "ServiceUnavailable",
	http.StatusInternalServerError: "InternalError", http.StatusBadGateway: "InternalError",
}

// refuse answers a Status; a wait asks the client to come back (client-go
// tries again on 429 and 503 with Retry-After).
func refuse(w http.ResponseWriter, code int, message string, wait time.Duration) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	if wait > 0 {
		header.Set("Retry-After", strconv.Itoa(max(1, int(wait.Round(time.Second)/time.Second))))
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(status{APIVersion: "v1", Kind: "Status", Status: "Failure", Message: message,
		Reason: reasons[code], Code: code})
}
