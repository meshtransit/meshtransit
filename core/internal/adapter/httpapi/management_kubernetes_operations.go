package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// kubernetesDefaultOperationRange is the range without from and to.
const kubernetesDefaultOperationRange = 24 * time.Hour

// kubernetesOperationQuery is what a GET of operations or denial counts
// asks; a zero from or to takes the default when served.
type kubernetesOperationQuery struct {
	from, to time.Time
	ownerRef string
	device   node.ID
	class    string
	page     kubernetesPage
}

// kubernetesOperationToken binds a cursor to its Network, cluster, range
// and filters: the range and filters come from the token on later pages.
type kubernetesOperationToken struct {
	Version     int    `json:"v"`
	WorkspaceID string `json:"w"`
	NetworkID   string `json:"n"`
	ClusterID   string `json:"c"`
	From        string `json:"f"`
	To          string `json:"u"`
	OwnerRef    string `json:"p,omitempty"`
	Device      string `json:"d,omitempty"`
	Class       string `json:"k,omitempty"`
	At          string `json:"t"`
	After       string `json:"a"`
}

func encodeKubernetesOperationToken(scope network.Scope, clusterID kubecluster.ID, query kubecluster.OperationQuery,
	cursor kubecluster.PageCursor) string {
	if cursor.IsZero() {
		return ""
	}
	token := kubernetesOperationToken{Version: 1, WorkspaceID: scope.WorkspaceID().String(),
		NetworkID: scope.NetworkID().String(), ClusterID: clusterID.String(), From: managementTime(query.From),
		To: managementTime(query.To), OwnerRef: query.OwnerRef, Class: query.Class,
		At: managementTime(cursor.At), After: cursor.ID.String()}
	if query.PeerDeviceID.IsValid() {
		token.Device = query.PeerDeviceID.String()
	}
	payload, err := json.Marshal(token)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

// parseKubernetesOperationQuery reads from, to and, for the operation list,
// person, device, class, page_size and page_token.
func parseKubernetesOperationQuery(raw string, scope network.Scope, clusterID kubecluster.ID,
	list bool) (kubernetesOperationQuery, bool) {
	query := kubernetesOperationQuery{page: kubernetesPage{limit: kubernetesDefaultPageSize}}
	if len(raw) > 2048 {
		return kubernetesOperationQuery{}, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return kubernetesOperationQuery{}, false
	}
	allowed := map[string]bool{"from": true, "to": true}
	if list {
		for _, key := range []string{"person", "device", "class", "page_size", "page_token"} {
			allowed[key] = true
		}
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || entries[0] == "" {
			return kubernetesOperationQuery{}, false
		}
	}
	for key, target := range map[string]*time.Time{"from": &query.from, "to": &query.to} {
		if value := values.Get(key); value != "" {
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || len(value) > 40 {
				return kubernetesOperationQuery{}, false
			}
			*target = at.UTC()
		}
	}
	query.ownerRef, query.class = values.Get("person"), values.Get("class")
	if len(query.ownerRef) > kubecluster.MaximumOwnerRef {
		return kubernetesOperationQuery{}, false
	}
	if value := values.Get("device"); value != "" {
		id, ok := canonicalPublicID(value)
		if !ok {
			return kubernetesOperationQuery{}, false
		}
		query.device = node.ID(id)
	}
	if value := values.Get("page_size"); value != "" {
		query.page.limit, err = strconv.Atoi(value)
		if err != nil || query.page.limit < 1 || query.page.limit > kubecluster.MaximumPageSize ||
			strconv.Itoa(query.page.limit) != value {
			return kubernetesOperationQuery{}, false
		}
	}
	if encoded := values.Get("page_token"); encoded != "" {
		return query.withToken(encoded, scope, clusterID)
	}
	return query, true
}

// withToken takes the range and filters of the token; any the query also
// names must match.
func (query kubernetesOperationQuery) withToken(encoded string, scope network.Scope,
	clusterID kubecluster.ID) (kubernetesOperationQuery, bool) {
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(encoded) > 2048 || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return kubernetesOperationQuery{}, false
	}
	var wire kubernetesOperationToken
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
		wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() ||
		wire.ClusterID != clusterID.String() {
		return kubernetesOperationQuery{}, false
	}
	from, fromErr := time.Parse(time.RFC3339Nano, wire.From)
	to, toErr := time.Parse(time.RFC3339Nano, wire.To)
	at, atErr := time.Parse(time.RFC3339Nano, wire.At)
	after, afterErr := publicid.Parse(wire.After)
	if fromErr != nil || toErr != nil || atErr != nil || afterErr != nil || !after.IsValid() {
		return kubernetesOperationQuery{}, false
	}
	var device node.ID
	if wire.Device != "" {
		id, ok := canonicalPublicID(wire.Device)
		if !ok {
			return kubernetesOperationQuery{}, false
		}
		device = node.ID(id)
	}
	if !query.from.IsZero() && !query.from.Equal(from) || !query.to.IsZero() && !query.to.Equal(to) ||
		query.ownerRef != "" && query.ownerRef != wire.OwnerRef || query.class != "" && query.class != wire.Class ||
		query.device.IsValid() && query.device != device {
		return kubernetesOperationQuery{}, false
	}
	query.from, query.to, query.ownerRef, query.class, query.device = from.UTC(), to.UTC(), wire.OwnerRef,
		wire.Class, device
	query.page.after = kubecluster.PageCursor{At: at.UTC(), ID: after}
	return query, true
}

// resolve fills a missing range: the day up to now, or the day up to to.
func (query kubernetesOperationQuery) resolve(now time.Time) (time.Time, time.Time) {
	to := query.to
	if to.IsZero() {
		to = now.UTC().Truncate(time.Second)
	}
	from := query.from
	if from.IsZero() {
		from = to.Add(-kubernetesDefaultOperationRange)
	}
	return from, to
}

type kubernetesOperationBody struct {
	AuditID         string   `json:"audit_id"`
	ReceivedAt      string   `json:"received_at"`
	Class           string   `json:"class"`
	Groups          []string `json:"groups"`
	Verb            string   `json:"verb"`
	APIGroup        string   `json:"api_group"`
	Resource        string   `json:"resource"`
	Subresource     string   `json:"subresource"`
	Namespace       string   `json:"namespace"`
	Name            string   `json:"name"`
	Impersonated    string   `json:"impersonated"`
	OwnerKind       string   `json:"owner_kind"`
	OwnerRef        string   `json:"owner_ref"`
	NetworkRevision int64    `json:"network_revision"`
	ClockSkew       bool     `json:"clock_skew"`
	GatewayDeviceID *string  `json:"gateway_device_id"`
	PeerDeviceID    *string  `json:"peer_device_id"`
	Status          *int     `json:"status"`
	DurationMS      *int     `json:"duration_ms"`
}

func newKubernetesOperationBody(operation kubecluster.Operation) kubernetesOperationBody {
	optionalDevice := func(id node.ID) *string {
		if !id.IsValid() {
			return nil
		}
		text := id.String()
		return &text
	}
	body := kubernetesOperationBody{AuditID: operation.AuditID.String(),
		ReceivedAt: managementTime(operation.ReceivedAt), Class: operation.Class, Groups: operation.Groups,
		Verb: operation.Verb, APIGroup: operation.APIGroup, Resource: operation.Resource,
		Subresource: operation.Subresource, Namespace: operation.Namespace, Name: operation.Name,
		Impersonated: operation.Impersonated, OwnerKind: operation.OwnerKind, OwnerRef: operation.OwnerRef,
		NetworkRevision: operation.NetworkRevision, ClockSkew: operation.ClockSkew,
		GatewayDeviceID: optionalDevice(operation.GatewayDeviceID),
		PeerDeviceID:    optionalDevice(operation.PeerDeviceID)}
	if operation.HasOutcome {
		status, duration := operation.Status, operation.DurationMS
		body.Status, body.DurationMS = &status, &duration
	}
	return body
}

// readKubernetesOperations serves a page of operations, one operation, or
// the denial counts (K1d d1c); all need audit.read, which Core checks.
func (handler *ManagementHandler) readKubernetesOperations(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	manager := handler.kubernetesClusters
	from, to := path.operations.resolve(time.Now())
	switch path.operation {
	case kubernetesOperationListOperation:
		query := kubecluster.OperationQuery{Session: session, Scope: path.scope, ClusterID: path.clusterID,
			From: from, To: to, After: path.operations.page.after, OwnerRef: path.operations.ownerRef,
			PeerDeviceID: path.operations.device, Class: path.operations.class, Limit: path.operations.page.limit}
		page, err := manager.ListOperations(ctx, query)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		bodies := make([]kubernetesOperationBody, len(page.Operations))
		for index, operation := range page.Operations {
			bodies[index] = newKubernetesOperationBody(operation)
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			From          string                    `json:"from"`
			To            string                    `json:"to"`
			Operations    []kubernetesOperationBody `json:"operations"`
			Truncated     bool                      `json:"scan_truncated"`
			NextPageToken string                    `json:"next_page_token,omitempty"`
		}{managementTime(from), managementTime(to), bodies, page.Truncated,
			encodeKubernetesOperationToken(path.scope, path.clusterID, query, page.Next)})
	case kubernetesOperationReadOperation:
		operation, err := manager.ReadOperation(ctx, session, path.scope, path.clusterID, path.auditID)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, newKubernetesOperationBody(operation))
	default:
		sums, err := manager.CountDenials(ctx, session, path.scope, path.clusterID, from, to)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		type denialBody struct {
			Reason  string `json:"reason"`
			Count   int64  `json:"count"`
			FirstAt string `json:"first_at"`
			LastAt  string `json:"last_at"`
		}
		bodies := make([]denialBody, len(sums.Counts))
		for index, count := range sums.Counts {
			bodies[index] = denialBody{count.Reason, count.Count, managementTime(count.FirstAt),
				managementTime(count.LastAt)}
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			From        string       `json:"from"`
			To          string       `json:"to"`
			Counts      []denialBody `json:"denial_counts"`
			Truncated   bool         `json:"truncated"`
			CountedFrom *string      `json:"counted_from"`
		}{managementTime(from), managementTime(to), bodies, sums.Truncated, optionalManagementTime(sums.CountedFrom)})
	}
	return "success"
}
