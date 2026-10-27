package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	kubernetesClusterListOperation    = "kubernetes_cluster_list"
	kubernetesClusterCreateOperation  = "kubernetes_cluster_create"
	kubernetesClusterReadOperation    = "kubernetes_cluster_read"
	kubernetesClusterDeleteOperation  = "kubernetes_cluster_delete"
	kubernetesJoinKeyListOperation    = "kubernetes_join_key_list"
	kubernetesJoinKeyIssueOperation   = "kubernetes_join_key_issue"
	kubernetesJoinKeyReadOperation    = "kubernetes_join_key_read"
	kubernetesJoinKeyRevokeOperation  = "kubernetes_join_key_revoke"
	kubernetesRequestListOperation    = "kubernetes_replica_request_list"
	kubernetesRequestReadOperation    = "kubernetes_replica_request_read"
	kubernetesRequestApproveOperation = "kubernetes_replica_request_approve"
	kubernetesRequestRejectOperation  = "kubernetes_replica_request_reject"
)

// KubernetesClusterManager manages a Network's Kubernetes clusters, their
// join keys and the requests replicas make to join (K1a1 plan §3).
type KubernetesClusterManager interface {
	Create(context.Context, kubecluster.Creation) (kubecluster.Cluster, error)
	Delete(context.Context, kubecluster.Deletion) (kubecluster.Cluster, error)
	List(context.Context, accountsession.Session, network.Scope) ([]kubecluster.Cluster, error)
	Read(context.Context, accountsession.Session, network.Scope, kubecluster.ID) (kubecluster.Detail, error)
	IssueJoinKey(context.Context, kubecluster.KeyRequest) (kubecluster.IssuedJoinKey, error)
	RevokeJoinKey(context.Context, kubecluster.KeyRevocation) (kubecluster.JoinKey, error)
	Approve(context.Context, kubecluster.Decision, string) (kubecluster.ReplicaRequestView, error)
	Reject(context.Context, kubecluster.Decision) (kubecluster.ReplicaRequestView, error)
}

type kubernetesClusterPath struct {
	scope     network.Scope
	clusterID kubecluster.ID
	keyID     enrollment.CredentialID
	requestID kubecluster.RequestID
	methods   restMethods
	// operation is what the request's method does at the path; empty when
	// the path does not accept the method.
	operation string
}

// parseKubernetesClusterPath matches, under /api/v1/workspaces/{ws}/networks/{net}:
//
//	GET|POST    kubernetes-clusters                                       list, create
//	GET|DELETE  kubernetes-clusters/{c}                                   read, delete
//	GET|POST    kubernetes-clusters/{c}/join-keys                         list, issue
//	GET         kubernetes-clusters/{c}/join-keys/{key}                   read
//	POST        kubernetes-clusters/{c}/join-keys/{key}/actions/revoke    revoke
//	GET         kubernetes-clusters/{c}/replica-requests                  list
//	GET         kubernetes-clusters/{c}/replica-requests/{r}              read
//	POST        kubernetes-clusters/{c}/replica-requests/{r}/actions/approve|reject
//
// None takes a query.
func parseKubernetesClusterPath(request *http.Request) (kubernetesClusterPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return kubernetesClusterPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 7 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "kubernetes-clusters" {
		return kubernetesClusterPath{}, false
	}
	workspaceID, workspaceOK := canonicalPublicID(segments[3])
	networkID, networkOK := canonicalPublicID(segments[5])
	if !workspaceOK || !networkOK {
		return kubernetesClusterPath{}, false
	}
	scope, err := network.NewScope(workspace.ID(workspaceID), network.ID(networkID))
	if err != nil {
		return kubernetesClusterPath{}, false
	}
	path := kubernetesClusterPath{scope: scope}
	rest := segments[7:]
	if len(rest) > 0 {
		cluster, ok := canonicalPublicID(rest[0])
		if !ok {
			return kubernetesClusterPath{}, false
		}
		path.clusterID = kubecluster.ID(cluster)
	}
	operations, ok := path.route(rest)
	if !ok {
		return kubernetesClusterPath{}, false
	}
	if path.methods.allows(request.Method) {
		path.operation = operations[request.Method]
	}
	return path, true
}

// route sets the methods of the path after the cluster collection and
// returns what each does.
func (path *kubernetesClusterPath) route(rest []string) (map[string]string, bool) {
	child := func(index int) (publicid.ID, bool) {
		if len(rest) <= index {
			return publicid.ID{}, false
		}
		return canonicalPublicID(rest[index])
	}
	switch {
	case len(rest) == 0:
		path.methods = collectionMethods
		return map[string]string{http.MethodGet: kubernetesClusterListOperation,
			http.MethodPost: kubernetesClusterCreateOperation}, true
	case len(rest) == 1:
		path.methods = restMethods{http.MethodGet, http.MethodDelete}
		return map[string]string{http.MethodGet: kubernetesClusterReadOperation,
			http.MethodDelete: kubernetesClusterDeleteOperation}, true
	case len(rest) == 2 && rest[1] == "join-keys":
		path.methods = collectionMethods
		return map[string]string{http.MethodGet: kubernetesJoinKeyListOperation,
			http.MethodPost: kubernetesJoinKeyIssueOperation}, true
	case len(rest) == 2 && rest[1] == "replica-requests":
		path.methods = restMethods{http.MethodGet}
		return map[string]string{http.MethodGet: kubernetesRequestListOperation}, true
	case (len(rest) == 3 || len(rest) == 5 && rest[3] == "actions" && rest[4] == "revoke") && rest[1] == "join-keys":
		key, ok := child(2)
		if !ok {
			return nil, false
		}
		path.keyID = enrollment.CredentialID(key)
		if len(rest) == 3 {
			path.methods = restMethods{http.MethodGet}
			return map[string]string{http.MethodGet: kubernetesJoinKeyReadOperation}, true
		}
		path.methods = restMethods{http.MethodPost}
		return map[string]string{http.MethodPost: kubernetesJoinKeyRevokeOperation}, true
	case len(rest) == 3 && rest[1] == "replica-requests":
		request, ok := child(2)
		if !ok {
			return nil, false
		}
		path.requestID, path.methods = kubecluster.RequestID(request), restMethods{http.MethodGet}
		return map[string]string{http.MethodGet: kubernetesRequestReadOperation}, true
	case len(rest) == 5 && rest[1] == "replica-requests" && rest[3] == "actions" &&
		(rest[4] == "approve" || rest[4] == "reject"):
		request, ok := child(2)
		if !ok {
			return nil, false
		}
		path.requestID, path.methods = kubecluster.RequestID(request), restMethods{http.MethodPost}
		operation := kubernetesRequestApproveOperation
		if rest[4] == "reject" {
			operation = kubernetesRequestRejectOperation
		}
		return map[string]string{http.MethodPost: operation}, true
	default:
		return nil, false
	}
}

// isKubernetesClusterOperation admits only the methods each path accepts.
func isKubernetesClusterOperation(request *http.Request) bool {
	path, ok := parseKubernetesClusterPath(request)
	return ok && path.methods.allows(request.Method)
}

// isKubernetesClusterRead admits the reads.
func isKubernetesClusterRead(request *http.Request) bool {
	return request != nil && request.Method == http.MethodGet && isKubernetesClusterOperation(request)
}

func (handler *ManagementHandler) handleKubernetesClusters(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath,
	session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	// A new key's secret is in a body; reads change with every decision.
	response.Header().Set("Cache-Control", "no-store")
	if nilContinuationDependency(handler.kubernetesClusters) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Kubernetes clusters are temporarily unavailable", Retryable: true})
	}
	manager := handler.kubernetesClusters
	switch path.operation {
	case kubernetesClusterListOperation:
		clusters, err := manager.List(ctx, session, path.scope)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		bodies := make([]kubernetesClusterBody, len(clusters))
		for index, cluster := range clusters {
			bodies[index] = newKubernetesClusterBody(cluster)
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			NetworkID string                  `json:"network_id"`
			Clusters  []kubernetesClusterBody `json:"kubernetes_clusters"`
		}{path.scope.NetworkID().String(), bodies})
	case kubernetesClusterCreateOperation:
		return handler.createKubernetesCluster(ctx, response, request, correlationID, path, session, fail)
	case kubernetesClusterReadOperation, kubernetesJoinKeyListOperation, kubernetesJoinKeyReadOperation,
		kubernetesRequestListOperation, kubernetesRequestReadOperation:
		return handler.readKubernetesCluster(ctx, response, correlationID, path, session, fail)
	case kubernetesClusterDeleteOperation:
		expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		cluster, err := manager.Delete(ctx, kubecluster.Deletion{Session: session, Scope: path.scope,
			ClusterID: path.clusterID, ExpectedVersion: expectedVersion, CorrelationID: correlationID})
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, newKubernetesClusterBody(cluster))
	case kubernetesJoinKeyIssueOperation:
		return handler.issueKubernetesJoinKey(ctx, response, request, correlationID, path, session, fail)
	case kubernetesJoinKeyRevokeOperation:
		var body struct{}
		if !readDeviceGroupBody(response, request, &body) {
			return fail(*invalidManagementRequest())
		}
		key, err := manager.RevokeJoinKey(ctx, kubecluster.KeyRevocation{Session: session, Scope: path.scope,
			ClusterID: path.clusterID, KeyID: path.keyID, CorrelationID: correlationID})
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, newKubernetesJoinKeyBody(key))
	case kubernetesRequestApproveOperation, kubernetesRequestRejectOperation:
		return handler.decideKubernetesRequest(ctx, response, request, correlationID, path, session, fail)
	default:
		return fail(*invalidManagementRequest())
	}
	return "success"
}

func writeKubernetesData(ctx context.Context, handler *ManagementHandler, response http.ResponseWriter,
	correlationID publicid.ID, status int, data any) {
	writeManagementJSON(ctx, handler.logger, response, status, struct {
		Data          any    `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}{data, correlationID.String()})
}

func (handler *ManagementHandler) createKubernetesCluster(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Name == nil {
		return fail(*invalidManagementRequest())
	}
	name, err := kubecluster.ParseName(*body.Name)
	if err != nil {
		return fail(*invalidManagementRequest())
	}
	id, err := publicid.New()
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	creation := kubecluster.Creation{Session: session, Scope: path.scope, ID: kubecluster.ID(id), Name: name,
		CorrelationID: correlationID}
	if body.Description != nil {
		creation.Description = *body.Description
	}
	cluster, err := handler.kubernetesClusters.Create(ctx, creation)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	response.Header().Set("ETag", strongVersionETag(cluster.Version()))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusCreated, newKubernetesClusterBody(cluster))
	return "success"
}

func (handler *ManagementHandler) issueKubernetesJoinKey(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	var body struct {
		Uses               *int   `json:"uses"`
		KeyLifetimeSeconds *int64 `json:"key_lifetime_seconds"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Uses == nil {
		return fail(*invalidManagementRequest())
	}
	keyRequest := kubecluster.KeyRequest{Session: session, Scope: path.scope, ClusterID: path.clusterID,
		Uses: *body.Uses, CorrelationID: correlationID}
	if body.KeyLifetimeSeconds != nil {
		seconds := *body.KeyLifetimeSeconds
		if seconds <= 0 || seconds > int64(kubecluster.MaximumJoinKeyLifetime/time.Second) {
			return fail(*invalidManagementRequest())
		}
		keyRequest.Lifetime = time.Duration(seconds) * time.Second
	}
	lifetime := keyRequest.Lifetime
	if lifetime == 0 {
		lifetime = kubecluster.DefaultJoinKeyLifetime
	}
	if !kubecluster.ValidJoinKey(lifetime, keyRequest.Uses) {
		return fail(*invalidManagementRequest())
	}
	issued, err := handler.kubernetesClusters.IssueJoinKey(ctx, keyRequest)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusCreated, struct {
		Key kubernetesJoinKeyBody `json:"join_key"`
		// Secret is shown only here; Core keeps a digest of it.
		Secret string `json:"secret"`
	}{newKubernetesJoinKeyBody(issued.Key), issued.Presentation.Reveal()})
	return "success"
}

// readKubernetesCluster answers the cluster's read and its keys' and
// requests' lists and items, all from one read of the cluster.
func (handler *ManagementHandler) readKubernetesCluster(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	detail, err := handler.kubernetesClusters.Read(ctx, session, path.scope, path.clusterID)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	body := newKubernetesClusterDetailBody(detail)
	notFound := managementError{Status: http.StatusNotFound, Code: "kubernetes_cluster_not_found",
		Message: "The Kubernetes cluster, key or request is not in this Network"}
	// A caller who may only read the Network sees no keys or requests.
	forbidden := classifyKubernetesClusterError(kubecluster.ErrForbidden)
	switch path.operation {
	case kubernetesJoinKeyListOperation, kubernetesJoinKeyReadOperation:
		if body.JoinKeys == nil {
			return fail(forbidden)
		}
	case kubernetesRequestListOperation, kubernetesRequestReadOperation:
		if body.Requests == nil {
			return fail(forbidden)
		}
	}
	switch path.operation {
	case kubernetesJoinKeyListOperation:
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			JoinKeys []kubernetesJoinKeyBody `json:"join_keys"`
		}{*body.JoinKeys})
	case kubernetesRequestListOperation:
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			Requests []kubernetesRequestBody `json:"replica_requests"`
		}{*body.Requests})
	case kubernetesJoinKeyReadOperation:
		for _, key := range valueOrEmpty(body.JoinKeys) {
			if key.KeyID == path.keyID.String() {
				writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, key)
				return "success"
			}
		}
		return fail(notFound)
	case kubernetesRequestReadOperation:
		for _, request := range valueOrEmpty(body.Requests) {
			if request.RequestID == path.requestID.String() {
				writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, request)
				return "success"
			}
		}
		return fail(notFound)
	default:
		response.Header().Set("ETag", strongVersionETag(detail.Cluster.Version()))
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, body)
	}
	return "success"
}

func valueOrEmpty[T any](values *[]T) []T {
	if values == nil {
		return nil
	}
	return *values
}

func (handler *ManagementHandler) decideKubernetesRequest(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	decision := kubecluster.Decision{Session: session, Scope: path.scope, ClusterID: path.clusterID,
		RequestID: path.requestID, CorrelationID: correlationID}
	var view kubecluster.ReplicaRequestView
	var err error
	if path.operation == kubernetesRequestApproveOperation {
		var body struct {
			Code *string `json:"code"`
		}
		if !readDeviceGroupBody(response, request, &body) || body.Code == nil {
			return fail(*invalidManagementRequest())
		}
		view, err = handler.kubernetesClusters.Approve(ctx, decision, *body.Code)
	} else {
		var body struct{}
		if !readDeviceGroupBody(response, request, &body) {
			return fail(*invalidManagementRequest())
		}
		view, err = handler.kubernetesClusters.Reject(ctx, decision)
	}
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, newKubernetesRequestBody(view))
	return "success"
}

type kubernetesClusterBody struct {
	ClusterID   string `json:"cluster_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	State       string `json:"state"`
	Replicas    int    `json:"replicas"`
	CreatedBy   string `json:"created_by_principal_id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Version     int64  `json:"version"`
}

func newKubernetesClusterBody(cluster kubecluster.Cluster) kubernetesClusterBody {
	return kubernetesClusterBody{
		ClusterID: cluster.ID().String(), Name: cluster.Name().String(), Description: cluster.Description(),
		State: string(cluster.State()), Replicas: cluster.Replicas(), CreatedBy: cluster.CreatedBy().String(),
		CreatedAt: managementTime(cluster.CreatedAt()), UpdatedAt: managementTime(cluster.UpdatedAt()),
		Version: cluster.Version(),
	}
}

type kubernetesJoinKeyBody struct {
	KeyID     string  `json:"key_id"`
	IssuedBy  string  `json:"issued_by_principal_id"`
	CreatedAt string  `json:"created_at"`
	ExpiresAt string  `json:"expires_at"`
	RevokedAt *string `json:"revoked_at"`
	Uses      int     `json:"uses"`
	Used      int     `json:"used"`
	State     string  `json:"state"`
}

func newKubernetesJoinKeyBody(key kubecluster.JoinKey) kubernetesJoinKeyBody {
	body := kubernetesJoinKeyBody{
		KeyID: key.ID().String(), IssuedBy: key.IssuedBy().String(), CreatedAt: managementTime(key.CreatedAt()),
		ExpiresAt: managementTime(key.ExpiresAt()), Uses: key.Uses(), Used: key.Used(), State: string(key.State()),
	}
	if !key.RevokedAt().IsZero() {
		revoked := managementTime(key.RevokedAt())
		body.RevokedAt = &revoked
	}
	return body
}

type kubernetesRequestBody struct {
	RequestID          string `json:"request_id"`
	ClusterID          string `json:"cluster_id"`
	KeyID              string `json:"key_id"`
	MachineFingerprint string `json:"machine_key_fingerprint"`
	NodeFingerprint    string `json:"node_key_fingerprint"`
	Hostname           string `json:"hostname"`
	// ReportedByPod is what the pod says about itself, unverified: show it
	// as text only.
	ReportedByPod      json.RawMessage `json:"reported_by_pod"`
	State              string          `json:"state"`
	FailedAttempts     int             `json:"failed_code_attempts"`
	RemainingAttempts  int             `json:"remaining_code_attempts"`
	ApprovedBy         *string         `json:"approved_by_principal_id"`
	ApprovedAt         *string         `json:"approved_at"`
	CompletionDeadline *string         `json:"completion_deadline"`
	ReservedOrdinal    *int            `json:"reserved_ordinal"`
	ReservedName       *string         `json:"reserved_name"`
	DeviceID           *string         `json:"device_id"`
	CreatedAt          string          `json:"created_at"`
	ExpiresAt          string          `json:"expires_at"`
	UpdatedAt          string          `json:"updated_at"`
}

func newKubernetesRequestBody(view kubecluster.ReplicaRequestView) kubernetesRequestBody {
	lifecycle := view.Lifecycle()
	reported := view.Reported()
	if len(reported) == 0 {
		reported = json.RawMessage(`{}`)
	}
	body := kubernetesRequestBody{
		RequestID: view.ID().String(), ClusterID: view.ClusterID().String(), KeyID: view.KeyID().String(),
		MachineFingerprint: view.MachineFingerprint(), NodeFingerprint: view.NodeFingerprint(),
		Hostname: view.Hostname(), ReportedByPod: reported, State: string(lifecycle.State()),
		FailedAttempts:    lifecycle.FailedAttempts(),
		RemainingAttempts: kubecluster.MaximumCodeAttempts - lifecycle.FailedAttempts(),
		CreatedAt:         managementTime(lifecycle.CreatedAt()), ExpiresAt: managementTime(lifecycle.ExpiresAt()),
		UpdatedAt: managementTime(view.UpdatedAt()),
	}
	if approver, approvedAt, deadline, approved := view.Approval(); approved {
		approverText, approvedText, deadlineText := approver.String(), managementTime(approvedAt),
			managementTime(deadline)
		body.ApprovedBy, body.ApprovedAt, body.CompletionDeadline = &approverText, &approvedText, &deadlineText
	}
	if ordinal, name, reserved := view.Reservation(); reserved {
		body.ReservedOrdinal, body.ReservedName = &ordinal, &name
	}
	if device, ok := view.DeviceID(); ok {
		deviceText := device.String()
		body.DeviceID = &deviceText
	}
	return body
}

type kubernetesReplicaBody struct {
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	Ordinal   int    `json:"ordinal"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// kubernetesClusterDetailBody is one cluster's read. JoinKeys and Requests
// are null for a caller who may only read the Network.
type kubernetesClusterDetailBody struct {
	Cluster  kubernetesClusterBody    `json:"kubernetes_cluster"`
	Replicas []kubernetesReplicaBody  `json:"replicas"`
	JoinKeys *[]kubernetesJoinKeyBody `json:"join_keys"`
	Requests *[]kubernetesRequestBody `json:"replica_requests"`
	// KeyWarnings sums the gateways' stale or contested keys of the last 7
	// days (schema 229); null like JoinKeys.
	KeyWarnings *kubernetesKeyWarningsBody `json:"key_warnings"`
}

type kubernetesKeyWarningBody struct {
	DeviceID   string `json:"device_id"`
	Hostname   string `json:"hostname"`
	Count24h   int    `json:"count_24h"`
	Count7d    int    `json:"count_7d"`
	LastAt     string `json:"last_at"`
	LastReason string `json:"last_reason"`
	KeyState   string `json:"key_state"`
}

type kubernetesKeyWarningsBody struct {
	Devices   []kubernetesKeyWarningBody `json:"devices"`
	Truncated bool                       `json:"truncated"`
}

func newKubernetesClusterDetailBody(detail kubecluster.Detail) kubernetesClusterDetailBody {
	body := kubernetesClusterDetailBody{Cluster: newKubernetesClusterBody(detail.Cluster),
		Replicas: make([]kubernetesReplicaBody, 0, len(detail.Replicas))}
	for _, replica := range detail.Replicas {
		body.Replicas = append(body.Replicas, kubernetesReplicaBody{DeviceID: replica.DeviceID.String(),
			Name: replica.Name, Ordinal: replica.Ordinal, State: replica.State,
			CreatedAt: managementTime(replica.CreatedAt)})
	}
	if detail.Keys != nil {
		keys := make([]kubernetesJoinKeyBody, 0, len(detail.Keys))
		for _, key := range detail.Keys {
			keys = append(keys, newKubernetesJoinKeyBody(key))
		}
		body.JoinKeys = &keys
	}
	if detail.KeyWarnings != nil {
		warnings := kubernetesKeyWarningsBody{Truncated: detail.KeyWarnings.Truncated,
			Devices: make([]kubernetesKeyWarningBody, 0, len(detail.KeyWarnings.Devices))}
		for _, warning := range detail.KeyWarnings.Devices {
			warnings.Devices = append(warnings.Devices, kubernetesKeyWarningBody{
				DeviceID: warning.DeviceID.String(), Hostname: warning.Hostname, Count24h: warning.Last24h,
				Count7d: warning.Last7Days, LastAt: managementTime(warning.LastAt),
				LastReason: string(warning.LastReason), KeyState: string(warning.KeyState),
			})
		}
		body.KeyWarnings = &warnings
	}
	if detail.Requests != nil {
		requests := make([]kubernetesRequestBody, 0, len(detail.Requests))
		for _, request := range detail.Requests {
			requests = append(requests, newKubernetesRequestBody(request))
		}
		body.Requests = &requests
	}
	return body
}

func classifyKubernetesClusterError(err error) managementError {
	var wrong *kubecluster.WrongCodeError
	switch {
	case errors.As(err, &wrong) && wrong.Remaining > 0:
		remaining := wrong.Remaining
		return managementError{Status: http.StatusUnprocessableEntity, Code: "join_code_wrong",
			Message:           fmt.Sprintf("The code does not match this request. %d attempts left.", remaining),
			RemainingAttempts: &remaining}
	case errors.As(err, &wrong):
		return managementError{Status: http.StatusConflict, Code: "replica_request_cancelled",
			Message: fmt.Sprintf("%d wrong codes cancelled the request. The replica asks again with a new request.",
				kubecluster.MaximumCodeAttempts)}
	case errors.Is(err, kubecluster.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot do this with the Kubernetes clusters of this Network"}
	case errors.Is(err, kubecluster.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "kubernetes_cluster_not_found",
			Message: "The Kubernetes cluster, key or request is not in this Network"}
	case errors.Is(err, kubecluster.ErrConflict):
		return managementError{Status: http.StatusConflict, Code: "kubernetes_cluster_conflict",
			Message: "The cluster changed, its name is taken, or it still has replicas or waiting requests"}
	case errors.Is(err, kubecluster.ErrEdgeBudget):
		message := "With one more replica, the replica would load more than 10,000 rule edges; narrow the rules to this cluster"
		if failure, ok := errors.AsType[*kubecluster.EdgeBudgetError](err); ok && failure.SourceDeviceID.IsValid() {
			message = "With one more replica, source Device " + failure.SourceDeviceID.String() +
				" would load more than 10,000 rule edges; narrow the rules to this cluster"
		}
		return managementError{Status: http.StatusConflict, Code: "device_policy_edge_limit", Message: message}
	case errors.Is(err, kubecluster.ErrLimitReached):
		return managementError{Status: http.StatusConflict, Code: "kubernetes_cluster_limit",
			Message: "The Network or cluster has as many clusters, keys or replicas as it may"}
	case errors.Is(err, kubecluster.ErrNotWaiting):
		return managementError{Status: http.StatusConflict, Code: "replica_request_not_waiting",
			Message: "The request was already approved, rejected, cancelled or expired"}
	case errors.Is(err, kubecluster.ErrKeyNotUsable):
		return managementError{Status: http.StatusConflict, Code: "join_key_not_usable",
			Message: "The join key is revoked, expired or used up; the request was cancelled"}
	// Schema 232 (K1.1): refusals that stay refusals.
	case errors.Is(err, kubecluster.ErrJoinAgain):
		return managementError{Status: http.StatusConflict, Code: "replica_must_rejoin",
			Message: "The request has no signing keys; it was cancelled. The replica must join again"}
	case errors.Is(err, kubecluster.ErrSigningMismatch):
		return managementError{Status: http.StatusConflict, Code: "replica_signing_mismatch",
			Message: "The replica's issuer, ServiceAccount or signing key differs from the cluster's"}
	case errors.Is(err, kubecluster.ErrPodHeld):
		return managementError{Status: http.StatusConflict, Code: "replica_pod_held",
			Message: "Another Device or approval holds this pod; remove it first"}
	case errors.Is(err, kubecluster.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload before trying again.", Retryable: true}
	}
}
