package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	kubernetesTestCluster = "01890f00-0000-7000-8000-000000000b01"
	kubernetesTestKey     = "01890f00-0000-7000-8000-000000000b02"
	kubernetesTestRequest = "01890f00-0000-7000-8000-000000000b03"
)

func kubernetesClustersTestPath(rest string) string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + networkMemberTestNetwork +
		"/kubernetes-clusters" + rest
}

type kubernetesClusterStub struct {
	readOnly     bool
	replacements []kubecluster.TrustReplacement
	replaceErr   error
	calls        []string
	creations    []kubecluster.Creation
	deletions    []kubecluster.Deletion
	keys         []kubecluster.KeyRequest
	decisions    []kubecluster.Decision
	codes        []string
	failure      error
	pages        []kubecluster.PageQuery
	// next is the cursor list pages return.
	next             kubecluster.PageCursor
	truncated        bool
	operationQueries []kubecluster.OperationQuery
	auditSettings    []kubecluster.AuditSettingsReplacement
	denialRanges     [][2]time.Time
}

func (stub *kubernetesClusterStub) ListJoinKeys(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.JoinKeyPage, error) {
	stub.calls = append(stub.calls, "list-keys")
	stub.pages = append(stub.pages, query)
	if err := stub.rowsFailure(); err != nil {
		return kubecluster.JoinKeyPage{}, err
	}
	return kubecluster.JoinKeyPage{Keys: []kubecluster.JoinKey{kubernetesTestKeyValue(&testing.T{},
		kubecluster.KeyActive)}, Next: stub.next}, nil
}

func (stub *kubernetesClusterStub) ReadJoinKey(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ kubecluster.ID, key enrollment.CredentialID) (kubecluster.JoinKey, error) {
	stub.calls = append(stub.calls, "read-key")
	if err := stub.rowsFailure(); err != nil {
		return kubecluster.JoinKey{}, err
	}
	if key.String() != kubernetesTestKey {
		return kubecluster.JoinKey{}, kubecluster.ErrNotFound
	}
	return kubernetesTestKeyValue(&testing.T{}, kubecluster.KeyActive), nil
}

func (stub *kubernetesClusterStub) ListReplicaRequests(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.RequestPage, error) {
	stub.calls = append(stub.calls, "list-requests")
	stub.pages = append(stub.pages, query)
	if err := stub.rowsFailure(); err != nil {
		return kubecluster.RequestPage{}, err
	}
	return kubecluster.RequestPage{Requests: []kubecluster.ReplicaRequestView{
		kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestPending)}, Next: stub.next}, nil
}

func (stub *kubernetesClusterStub) ReadReplicaRequest(_ context.Context, _ accountsession.Session,
	_ network.Scope, _ kubecluster.ID, request kubecluster.RequestID) (kubecluster.ReplicaRequestView, error) {
	stub.calls = append(stub.calls, "read-request")
	if err := stub.rowsFailure(); err != nil {
		return kubecluster.ReplicaRequestView{}, err
	}
	if request.String() != kubernetesTestRequest {
		return kubecluster.ReplicaRequestView{}, kubecluster.ErrNotFound
	}
	return kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestPending), nil
}

func (stub *kubernetesClusterStub) ListReplicas(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.ReplicaPage, error) {
	stub.calls = append(stub.calls, "list-replicas")
	stub.pages = append(stub.pages, query)
	if stub.failure != nil {
		return kubecluster.ReplicaPage{}, stub.failure
	}
	return kubecluster.ReplicaPage{Replicas: []kubecluster.Replica{kubernetesTestReplica()}, Next: stub.next}, nil
}

func (stub *kubernetesClusterStub) ReadReplica(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ kubecluster.ID, device node.ID) (kubecluster.Replica, error) {
	stub.calls = append(stub.calls, "read-replica")
	if stub.failure != nil {
		return kubecluster.Replica{}, stub.failure
	}
	if device != kubernetesTestDevice() {
		return kubecluster.Replica{}, kubecluster.ErrNotFound
	}
	return kubernetesTestReplica(), nil
}

func (stub *kubernetesClusterStub) ListCertificateAuthorities(_ context.Context,
	query kubecluster.PageQuery) (kubecluster.CAPage, error) {
	stub.calls = append(stub.calls, "list-cas")
	stub.pages = append(stub.pages, query)
	if stub.failure != nil {
		return kubecluster.CAPage{}, stub.failure
	}
	return kubecluster.CAPage{CAs: []kubecluster.CertificateAuthority{kubernetesTestCA()}, Next: stub.next}, nil
}

func (stub *kubernetesClusterStub) ReadCertificateAuthority(_ context.Context, _ accountsession.Session,
	_ network.Scope, _ kubecluster.ID, ca publicid.ID) (kubecluster.CertificateAuthority, error) {
	stub.calls = append(stub.calls, "read-ca")
	if stub.failure != nil {
		return kubecluster.CertificateAuthority{}, stub.failure
	}
	if ca != kubernetesTestCA().ID {
		return kubecluster.CertificateAuthority{}, kubecluster.ErrNotFound
	}
	return kubernetesTestCA(), nil
}

func (stub *kubernetesClusterStub) ListOperations(_ context.Context,
	query kubecluster.OperationQuery) (kubecluster.OperationPage, error) {
	stub.calls = append(stub.calls, "list-operations")
	stub.operationQueries = append(stub.operationQueries, query)
	if stub.failure != nil {
		return kubecluster.OperationPage{}, stub.failure
	}
	return kubecluster.OperationPage{Operations: []kubecluster.Operation{kubernetesTestOperation()},
		Next: stub.next, Truncated: stub.truncated}, nil
}

func (stub *kubernetesClusterStub) ReadOperation(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ kubecluster.ID, auditID publicid.ID) (kubecluster.Operation, error) {
	stub.calls = append(stub.calls, "read-operation")
	if stub.failure != nil {
		return kubecluster.Operation{}, stub.failure
	}
	if auditID != kubernetesTestOperation().AuditID {
		return kubecluster.Operation{}, kubecluster.ErrNotFound
	}
	return kubernetesTestOperation(), nil
}

func (stub *kubernetesClusterStub) CountDenials(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ kubecluster.ID, from, to time.Time) (kubecluster.DenialSums, error) {
	stub.calls = append(stub.calls, "count-denials")
	stub.denialRanges = append(stub.denialRanges, [2]time.Time{from, to})
	if stub.failure != nil {
		return kubecluster.DenialSums{}, stub.failure
	}
	return kubecluster.DenialSums{Counts: []kubecluster.DenialCount{{Reason: "forbidden", Count: 3, FirstAt: from,
		LastAt: to}}}, nil
}

func (stub *kubernetesClusterStub) ReadAuditSettings(context.Context, accountsession.Session, network.Scope,
	kubecluster.ID) (kubecluster.AuditSettings, error) {
	stub.calls = append(stub.calls, "read-audit-settings")
	if stub.failure != nil {
		return kubecluster.AuditSettings{}, stub.failure
	}
	return kubecluster.AuditSettings{PrivilegedGroups: []string{"sre"}, SecretResources: []string{}, Version: 2,
		UpdatedAt: time.Date(2026, time.October, 30, 2, 0, 0, 0, time.UTC)}, nil
}

func (stub *kubernetesClusterStub) ReplaceAuditSettings(_ context.Context,
	replacement kubecluster.AuditSettingsReplacement) (kubecluster.AuditSettingsResult, error) {
	stub.calls = append(stub.calls, "replace-audit-settings")
	stub.auditSettings = append(stub.auditSettings, replacement)
	if stub.failure != nil {
		return kubecluster.AuditSettingsResult{}, stub.failure
	}
	return kubecluster.AuditSettingsResult{Changed: true, Settings: kubecluster.AuditSettings{
		PrivilegedGroups: replacement.PrivilegedGroups, SecretResources: replacement.SecretResources,
		Version: replacement.ExpectedVersion + 1, UpdatedAt: time.Date(2026, time.October, 30, 2, 0, 0, 0, time.UTC)}}, nil
}

const kubernetesTestAuditID = "01890f00-0000-7000-8000-000000000b08"

func kubernetesTestOperation() kubecluster.Operation {
	id, _ := publicid.Parse(kubernetesTestAuditID)
	return kubecluster.Operation{AuditID: id, ReceivedAt: time.Date(2026, time.October, 29, 13, 14, 58, 0, time.UTC),
		Class: "write", Groups: []string{"edit"}, Verb: "delete", Resource: "pods", Namespace: "default",
		Name: "diff-target", OwnerKind: "member", OwnerRef: "01890f00-0000-7000-8000-000000000011",
		NetworkRevision: 51, GatewayDeviceID: kubernetesTestDevice(), PeerDeviceID: kubernetesTestDevice(),
		HasOutcome: true, Status: 200, DurationMS: 12}
}

func kubernetesTestReplica() kubecluster.Replica {
	created := time.Date(2026, time.October, 26, 8, 0, 0, 0, time.UTC)
	return kubecluster.Replica{DeviceID: kubernetesTestDevice(), Name: "prod-0", Ordinal: 0, State: "active",
		CreatedAt: created, TokenFirstProvenAt: created.Add(time.Minute)}
}

const kubernetesTestCAID = "01890f00-0000-7000-8000-000000000b07"

func kubernetesTestCA() kubecluster.CertificateAuthority {
	id, _ := publicid.Parse(kubernetesTestCAID)
	created := time.Date(2026, time.October, 26, 1, 18, 0, 0, time.UTC)
	return kubecluster.CertificateAuthority{ID: id, Kind: kubecluster.CARoot, State: "active", Reason: "admin",
		StateReason: "admin", Fingerprint: strings.Repeat("9a", 32), Certificate: []byte("der bytes of a root"),
		ClusterDNSName: "kinda-k1.kube.example.mesh.internal", NotBefore: created,
		NotAfter: created.AddDate(10, 0, 0), CreatedAt: created, ActivatedAt: created, Version: 2}
}

// rowsFailure is what Core answers a reader of keys and requests: a
// reader of the Network alone is forbidden.
func (stub *kubernetesClusterStub) rowsFailure() error {
	if stub.failure != nil {
		return stub.failure
	}
	if stub.readOnly {
		return kubecluster.ErrForbidden
	}
	return nil
}

func kubernetesTestClusterValue(t testing.TB) kubecluster.Cluster {
	id, _ := kubecluster.ParseID(kubernetesTestCluster)
	creator, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	created := time.Date(2026, time.October, 25, 8, 0, 0, 0, time.UTC)
	cluster, err := kubecluster.NewCluster(kubecluster.ClusterParams{
		ID: id, Name: "prod", Description: "EKS Singapore", State: kubecluster.StateActive, Version: 3,
		Replicas: 1, CreatedBy: creator, CreatedAt: created, UpdatedAt: created,
	})
	if err != nil {
		t.Fatalf("NewCluster() error = %v", err)
	}
	return cluster
}

func kubernetesTestKeyValue(t testing.TB, state kubecluster.KeyState) kubecluster.JoinKey {
	id, _ := enrollment.ParseCredentialID(kubernetesTestKey)
	issuer, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	created := time.Date(2026, time.October, 25, 8, 0, 0, 0, time.UTC)
	params := kubecluster.JoinKeyParams{ID: id, IssuedBy: issuer, CreatedAt: created,
		ExpiresAt: created.Add(time.Hour), Uses: 2, State: state, Version: 1}
	if state == kubecluster.KeyRevoked {
		params.RevokedAt = created.Add(time.Minute)
	}
	key, err := kubecluster.NewJoinKey(params)
	if err != nil {
		t.Fatalf("NewJoinKey() error = %v", err)
	}
	return key
}

func kubernetesTestRequestValue(t testing.TB, state kubecluster.RequestState) kubecluster.ReplicaRequestView {
	id, _ := kubecluster.ParseRequestID(kubernetesTestRequest)
	cluster, _ := kubecluster.ParseID(kubernetesTestCluster)
	key, _ := enrollment.ParseCredentialID(kubernetesTestKey)
	created := time.Date(2026, time.October, 25, 8, 0, 0, 0, time.UTC)
	lifecycle, err := kubecluster.NewRequest(kubecluster.RequestParams{
		State: state, FailedAttempts: 1, CreatedAt: created, ExpiresAt: created.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	params := kubecluster.ReplicaRequestParams{
		ID: id, ClusterID: cluster, KeyID: key, MachineFingerprint: strings.Repeat("a", 64),
		NodeFingerprint: strings.Repeat("b", 64), Hostname: "meshgw-0",
		Reported: []byte(`{"pod":"meshgw-0"}`), Lifecycle: lifecycle, Version: 2, UpdatedAt: created,
	}
	if state == kubecluster.RequestApproved {
		params.ApprovedBy, _ = identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
		params.ApprovedAt, params.CompletionDeadline = created, created.Add(15*time.Minute)
		params.ReservedOrdinal, params.ReservedHostname = 0, "prod-0"
	}
	view, err := kubecluster.NewReplicaRequestView(params)
	if err != nil {
		t.Fatalf("NewReplicaRequestView() error = %v", err)
	}
	return view
}

func (stub *kubernetesClusterStub) Create(_ context.Context, creation kubecluster.Creation) (kubecluster.Cluster,
	error) {
	stub.calls, stub.creations = append(stub.calls, "create"), append(stub.creations, creation)
	if stub.failure != nil {
		return kubecluster.Cluster{}, stub.failure
	}
	return kubernetesTestClusterValue(&testing.T{}), nil
}

func (stub *kubernetesClusterStub) Delete(_ context.Context, deletion kubecluster.Deletion) (kubecluster.Cluster,
	error) {
	stub.calls, stub.deletions = append(stub.calls, "delete"), append(stub.deletions, deletion)
	if stub.failure != nil {
		return kubecluster.Cluster{}, stub.failure
	}
	return kubernetesTestClusterValue(&testing.T{}), nil
}

func (stub *kubernetesClusterStub) List(context.Context, accountsession.Session,
	network.Scope) ([]kubecluster.Cluster, error) {
	stub.calls = append(stub.calls, "list")
	if stub.failure != nil {
		return nil, stub.failure
	}
	return []kubecluster.Cluster{kubernetesTestClusterValue(&testing.T{})}, nil
}

func (stub *kubernetesClusterStub) ReplaceTrust(_ context.Context,
	replacement kubecluster.TrustReplacement) (kubecluster.TrustReplacementResult, error) {
	stub.calls, stub.replacements = append(stub.calls, "replace"), append(stub.replacements, replacement)
	if stub.replaceErr != nil {
		return kubecluster.TrustReplacementResult{}, stub.replaceErr
	}
	return kubecluster.TrustReplacementResult{Changed: true, Trust: kubecluster.SigningTrust{
		Issuer: replacement.Issuer, KeyThumbprints: [][32]byte{{0xab}}, Keys: kubecluster.TrustKeysOf(replacement.JWKS),
		Namespace: replacement.Namespace, ServiceAccount: replacement.ServiceAccount,
		StatefulSet: replacement.StatefulSet, Version: replacement.ExpectedVersion + 1,
		Source: kubecluster.TrustFromAdminPaste, SetAt: time.Date(2026, time.October, 27, 15, 0, 0, 0, time.UTC)}}, nil
}

func (stub *kubernetesClusterStub) ReadSigning(context.Context, accountsession.Session, network.Scope,
	kubecluster.ID) (kubecluster.Signing, error) {
	stub.calls = append(stub.calls, "signing")
	if stub.failure != nil {
		return kubecluster.Signing{}, stub.failure
	}
	deviceID, _ := node.ParseID("01890f00-0000-7000-8000-000000000b04")
	requestID, _ := kubecluster.ParseRequestID(kubernetesTestRequest)
	rotated := time.Date(2026, time.October, 27, 11, 14, 22, 0, time.UTC)
	signing := kubecluster.Signing{
		Trust: &kubecluster.SigningTrust{Issuer: "https://kubernetes.default.svc.cluster.local",
			KeyThumbprints: [][32]byte{{0xab}}, Namespace: "mt-kube-k1", ServiceAccount: "meshgw",
			StatefulSet: "meshgw", Version: 1, Source: kubecluster.TrustFromReplicaApproval,
			SetAt: time.Date(2026, time.October, 27, 10, 55, 0, 0, time.UTC)},
		Replicas: []kubecluster.ReplicaSigning{{DeviceID: deviceID, PodName: "meshgw-0", LastTokenRotation: rotated},
			{DeviceID: deviceID, PodName: "meshgw-1"}},
	}
	if stub.readOnly {
		return signing, nil
	}
	heldID, _ := kubecluster.ParseRequestID("01890f00-0000-7000-8000-000000000f02")
	signing.Requests = []kubecluster.RequestSigning{{RequestID: requestID, CodeVersion: 2,
		Issuer: "https://kubernetes.default.svc.cluster.local", Namespace: "mt-kube-k1", ServiceAccount: "meshgw",
		StatefulSet: "meshgw", PodName: "meshgw-1", JoinKeyThumbprint: [32]byte{0xcd}},
		{RequestID: heldID, CodeVersion: 2, Issuer: "https://kubernetes.default.svc.cluster.local",
			Namespace: "mt-kube-k1", ServiceAccount: "meshgw", StatefulSet: "meshgw", PodName: "meshgw-0",
			JoinKeyThumbprint: [32]byte{0xab}}}
	signing.RequestsTruncated = true
	signing.TokenWarnings = &kubecluster.KeyWarnings{Devices: []kubecluster.KeyWarning{{DeviceID: deviceID,
		Hostname: "prod-0", Last24h: 1, Last7Days: 2, LastAt: rotated, LastReason: kubecluster.KeyEventTokenMissing,
		KeyState: kubecluster.ReportedKeyCurrent}}}
	return signing, nil
}

func (stub *kubernetesClusterStub) Read(context.Context, accountsession.Session, network.Scope,
	kubecluster.ID) (kubecluster.Detail, error) {
	stub.calls = append(stub.calls, "read")
	if stub.failure != nil {
		return kubecluster.Detail{}, stub.failure
	}
	if stub.readOnly {
		return kubecluster.Detail{Cluster: kubernetesTestClusterValue(&testing.T{}), Replicas: []kubecluster.Replica{}}, nil
	}
	return kubecluster.Detail{
		Cluster:  kubernetesTestClusterValue(&testing.T{}),
		Replicas: []kubecluster.Replica{},
		Keys:     []kubecluster.JoinKey{kubernetesTestKeyValue(&testing.T{}, kubecluster.KeyActive)},
		Requests: []kubecluster.ReplicaRequestView{kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestPending)},
		KeyWarnings: &kubecluster.KeyWarnings{Devices: []kubecluster.KeyWarning{{
			DeviceID: kubernetesTestDevice(), Hostname: "prod-0", Last24h: 1, Last7Days: 3,
			LastAt:     time.Date(2026, time.October, 26, 9, 0, 0, 0, time.UTC),
			LastReason: kubecluster.KeyEventRetiredMachineKey, KeyState: kubecluster.ReportedKeyRotated,
		}}},
	}, nil
}

func (stub *kubernetesClusterStub) IssueJoinKey(_ context.Context,
	request kubecluster.KeyRequest) (kubecluster.IssuedJoinKey, error) {
	stub.calls, stub.keys = append(stub.calls, "issue"), append(stub.keys, request)
	if stub.failure != nil {
		return kubecluster.IssuedJoinKey{}, stub.failure
	}
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index)
	}
	token, _ := enrollment.NewCredentialToken(secret)
	key := kubernetesTestKeyValue(&testing.T{}, kubecluster.KeyActive)
	presentation, _ := enrollment.NewJoinKeyPresentation(key.ID(), token)
	return kubecluster.IssuedJoinKey{Key: key, Presentation: presentation}, nil
}

func (stub *kubernetesClusterStub) RevokeJoinKey(context.Context, kubecluster.KeyRevocation) (kubecluster.JoinKey,
	error) {
	stub.calls = append(stub.calls, "revoke")
	if stub.failure != nil {
		return kubecluster.JoinKey{}, stub.failure
	}
	return kubernetesTestKeyValue(&testing.T{}, kubecluster.KeyRevoked), nil
}

func (stub *kubernetesClusterStub) Approve(_ context.Context, decision kubecluster.Decision,
	typed string) (kubecluster.ReplicaRequestView, error) {
	stub.calls, stub.decisions, stub.codes = append(stub.calls, "approve"), append(stub.decisions, decision),
		append(stub.codes, typed)
	if stub.failure != nil {
		return kubecluster.ReplicaRequestView{}, stub.failure
	}
	return kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestApproved), nil
}

func (stub *kubernetesClusterStub) Reject(_ context.Context,
	decision kubecluster.Decision) (kubecluster.ReplicaRequestView, error) {
	stub.calls, stub.decisions = append(stub.calls, "reject"), append(stub.decisions, decision)
	if stub.failure != nil {
		return kubecluster.ReplicaRequestView{}, stub.failure
	}
	return kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestRejected), nil
}

func TestParseKubernetesClusterPath(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	for _, test := range []struct {
		method, path string
		valid        bool
		operation    string
	}{
		{http.MethodGet, kubernetesClustersTestPath(""), true, kubernetesClusterListOperation},
		{http.MethodPost, kubernetesClustersTestPath(""), true, kubernetesClusterCreateOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster), true, kubernetesClusterReadOperation},
		{http.MethodDelete, kubernetesClustersTestPath(cluster), true, kubernetesClusterDeleteOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/join-keys"), true, kubernetesJoinKeyListOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/join-keys"), true, kubernetesJoinKeyIssueOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/join-keys/" + kubernetesTestKey), true,
			kubernetesJoinKeyReadOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/join-keys/" + kubernetesTestKey + "/actions/revoke"),
			true, kubernetesJoinKeyRevokeOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/replica-requests"), true,
			kubernetesRequestListOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/signing"), true, kubernetesClusterSigningOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/signing-trust"), true,
			kubernetesSigningTrustReadOperation},
		{http.MethodPut, kubernetesClustersTestPath(cluster + "/signing-trust"), true,
			kubernetesSigningTrustReplaceOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest), true,
			kubernetesRequestReadOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest +
			"/actions/approve"), true, kubernetesRequestApproveOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest +
			"/actions/reject"), true, kubernetesRequestRejectOperation},
		{http.MethodGet, kubernetesClustersTestPath("?name=prod"), false, ""},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest +
			"/actions/delete"), false, ""},
		{http.MethodGet, kubernetesClustersTestPath("/" + strings.ToUpper(kubernetesTestCluster)), false, ""},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/replicas"), true, kubernetesReplicaListOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/certificate-authorities"), true,
			kubernetesCAListOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/replicas/x"), false, ""},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/certificate-authorities/" + kubernetesTestCAID +
			"/actions/retire"), false, ""},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseKubernetesClusterPath(request)
		if ok != test.valid {
			t.Errorf("%s %s: matched = %t, want %t", test.method, test.path, ok, test.valid)
			continue
		}
		if ok && (path.operation != test.operation || !isKubernetesClusterOperation(request)) {
			t.Errorf("%s %s: operation %q, want %q", test.method, test.path, path.operation, test.operation)
		}
	}
	if isKubernetesClusterOperation(httptest.NewRequestWithContext(t.Context(), http.MethodPatch,
		kubernetesClustersTestPath("/"+kubernetesTestCluster), nil)) {
		t.Error("PATCH on a cluster was admitted")
	}
	if !isKubernetesClusterRead(httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		kubernetesClustersTestPath(""), nil)) || isKubernetesClusterRead(httptest.NewRequestWithContext(t.Context(),
		http.MethodPost, kubernetesClustersTestPath(""), nil)) {
		t.Error("isKubernetesClusterRead admits the wrong requests")
	}
}

func TestKubernetesClusterHTTPBoundary(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	request := cluster + "/replica-requests/" + kubernetesTestRequest
	secret := base64.RawURLEncoding.EncodeToString([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
		30, 31})
	for _, test := range []struct {
		name, method, path, body string
		ifMatch                  string
		failure                  error
		status                   int
		call                     string
		want, absent             string
	}{
		{"list", http.MethodGet, "", "", "", nil, 200, "list", `"name":"prod"`, ""},
		{"create", http.MethodPost, "", `{"name":"prod","description":"EKS Singapore"}`, "", nil, 201, "create",
			`"cluster_id":"` + kubernetesTestCluster + `"`, ""},
		{"create upper case", http.MethodPost, "", `{"name":"Prod"}`, "", nil, 400, "", "invalid_request", ""},
		{"create unknown field", http.MethodPost, "", `{"name":"prod","replicas":2}`, "", nil, 400, "",
			"invalid_request", ""},
		{"create taken", http.MethodPost, "", `{"name":"prod"}`, "", kubecluster.ErrConflict, 409, "create",
			"kubernetes_cluster_conflict", ""},
		{"create forbidden", http.MethodPost, "", `{"name":"prod"}`, "", kubecluster.ErrForbidden, 403, "create",
			"permission_denied", ""},
		{"read", http.MethodGet, cluster, "", "", nil, 200, "read", `"replica_requests":[{`, ""},
		{"read unknown", http.MethodGet, cluster, "", "", kubecluster.ErrNotFound, 404, "read",
			"kubernetes_cluster_not_found", ""},
		{"delete", http.MethodDelete, cluster, "", `"3"`, nil, 200, "delete", `"name":"prod"`, ""},
		{"delete with replicas", http.MethodDelete, cluster, "", `"3"`, kubecluster.ErrConflict, 409, "delete",
			"kubernetes_cluster_conflict", ""},
		{"issue", http.MethodPost, cluster + "/join-keys", `{"uses":2}`, "", nil, 201, "issue",
			`"secret":"mtk1.` + kubernetesTestKey + `.` + secret + `"`, ""},
		{"issue an hour", http.MethodPost, cluster + "/join-keys", `{"uses":1,"key_lifetime_seconds":3600}`, "", nil,
			201, "issue", `"uses":2`, ""},
		{"issue no uses", http.MethodPost, cluster + "/join-keys", `{}`, "", nil, 400, "", "invalid_request", ""},
		{"issue too long", http.MethodPost, cluster + "/join-keys", `{"uses":1,"key_lifetime_seconds":3601}`, "",
			nil, 400, "", "invalid_request", ""},
		{"list keys", http.MethodGet, cluster + "/join-keys", "", "", nil, 200, "list-keys", `"join_keys":[{`, secret},
		{"list keys, a page", http.MethodGet, cluster + "/join-keys?page_size=100", "", "", nil, 200, "list-keys",
			`"join_keys":[{`, "next_page_token"},
		{"list keys, page too big", http.MethodGet, cluster + "/join-keys?page_size=101", "", "", nil, 404, "", "", ""},
		{"list keys, other query", http.MethodGet, cluster + "/join-keys?limit=10", "", "", nil, 404, "", "", ""},
		{"read a key", http.MethodGet, cluster + "/join-keys/" + kubernetesTestKey, "", "", nil, 200, "read-key",
			`"key_id":"` + kubernetesTestKey + `"`, secret},
		{"revoke", http.MethodPost, cluster + "/join-keys/" + kubernetesTestKey + "/actions/revoke", `{}`, "", nil,
			200, "revoke", `"state":"revoked"`, ""},
		{"list requests", http.MethodGet, cluster + "/replica-requests", "", "", nil, 200, "list-requests",
			`"reported_by_pod":{"pod":"meshgw-0"}`, ""},
		{"list replicas", http.MethodGet, cluster + "/replicas?page_size=10", "", "", nil, 200, "list-replicas",
			`"token_first_proven_at":"2026-10-26T08:01:00Z"`, ""},
		{"read a replica", http.MethodGet, cluster + "/replicas/" + kubernetesTestDevice().String(), "", "", nil, 200,
			"read-replica", `"name":"prod-0"`, ""},
		{"list CAs", http.MethodGet, cluster + "/certificate-authorities", "", "", nil, 200, "list-cas",
			`"fingerprint_sha256":"` + strings.Repeat("9a", 32) + `"`, "changed_by\""},
		{"read a CA", http.MethodGet, cluster + "/certificate-authorities/" + kubernetesTestCAID, "", "", nil, 200,
			"read-ca", `"certificate_pem":"-----BEGIN CERTIFICATE-----\n`, ""},
		{"read an unknown CA", http.MethodGet, cluster + "/certificate-authorities/" + kubernetesTestKey, "", "",
			nil, 404, "read-ca", "kubernetes_cluster_not_found", ""},
		{"a CA page over 50", http.MethodGet, cluster + "/certificate-authorities?page_size=51", "", "", nil, 404,
			"", "", ""},
		{"a replica page of 100", http.MethodGet, cluster + "/replicas?page_size=100", "", "", nil, 200,
			"list-replicas", `"replicas":[`, ""},
		{"a CA takes no query", http.MethodGet, cluster + "/certificate-authorities/" + kubernetesTestCAID +
			"?page_size=1", "", "", nil, 404, "", "", ""},
		{"no POST on replicas", http.MethodPost, cluster + "/replicas", `{}`, "", nil, 405, "", "method_not_allowed",
			""},
		{"list operations", http.MethodGet, cluster + "/operations", "", "", nil, 200, "list-operations",
			`"name":"diff-target","impersonated":"","owner_kind":"member"`, "token_id"},
		{"list operations, a filter", http.MethodGet, cluster + "/operations?class=write&person=x&device=" +
			kubernetesTestDevice().String(), "", "", nil, 200, "list-operations", `"scan_truncated":false`, ""},
		{"list operations, a range", http.MethodGet, cluster + "/operations?from=2026-10-29T00:00:00Z&to=" +
			"2026-10-30T00:00:00Z", "", "", nil, 200, "list-operations", `"from":"2026-10-29T00:00:00Z"`, ""},
		{"operations, a bad time", http.MethodGet, cluster + "/operations?from=yesterday", "", "", nil, 404, "", "",
			""},
		{"operations, an unknown query", http.MethodGet, cluster + "/operations?verb=delete", "", "", nil, 404, "",
			"", ""},
		{"read an operation", http.MethodGet, cluster + "/operations/" + kubernetesTestAuditID, "", "", nil, 200,
			"read-operation", `"status":200,"duration_ms":12`, ""},
		{"denial counts", http.MethodGet, cluster + "/operation-denial-counts?from=2026-10-29T00:00:00Z", "", "",
			nil, 200, "count-denials", `"reason":"forbidden","count":3`, ""},
		{"denial counts take no class", http.MethodGet, cluster + "/operation-denial-counts?class=write", "", "",
			nil, 404, "", "", ""},
		{"operations without audit.read", http.MethodGet, cluster + "/operations", "", "", kubecluster.ErrForbidden,
			403, "list-operations", "", ""},
		{"read audit settings", http.MethodGet, cluster + "/audit-settings", "", "", nil, 200,
			"read-audit-settings", `"privileged_groups":["sre"],"secret_resources":[],"version":2`, ""},
		{"set audit settings first", http.MethodPut, cluster + "/audit-settings",
			`{"privileged_groups":["sre"],"secret_resources":["secrets"]}`, `"0"`, nil, 200, "replace-audit-settings",
			`"version":1`, ""},
		{"replace audit settings", http.MethodPut, cluster + "/audit-settings",
			`{"privileged_groups":[],"secret_resources":[]}`, `"2"`, nil, 200, "replace-audit-settings",
			`"changed":true`, ""},
		{"audit settings without If-Match", http.MethodPut, cluster + "/audit-settings",
			`{"privileged_groups":[],"secret_resources":[]}`, "", nil, 428, "", "precondition_required", ""},
		{"audit settings without a list", http.MethodPut, cluster + "/audit-settings", `{"privileged_groups":[]}`,
			`"0"`, nil, 400, "", "invalid_request", ""},
		{"stale audit settings", http.MethodPut, cluster + "/audit-settings",
			`{"privileged_groups":[],"secret_resources":[]}`, `"1"`, kubecluster.ErrConflict, 409,
			"replace-audit-settings", "", ""},
		{"read a request", http.MethodGet, request, "", "", nil, 200, "read-request",
			`"machine_key_fingerprint":"` + strings.Repeat("a", 64) + `"`, ""},
		{"approve", http.MethodPost, request + "/actions/approve", `{"code":"4KH7I-REC2B"}`, "", nil, 200,
			"approve", `"reserved_name":"prod-0"`, ""},
		{"approve without a code", http.MethodPost, request + "/actions/approve", `{}`, "", nil, 400, "",
			"invalid_request", ""},
		{"approve a malformed code", http.MethodPost, request + "/actions/approve", `{"code":"x"}`, "",
			kubecluster.ErrInvalid, 400, "approve", "invalid_request", ""},
		{"approve a wrong code", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			&kubecluster.WrongCodeError{Remaining: 3}, 422, "approve", `"remaining_attempts":3`, ""},
		{"approve the last wrong code", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			&kubecluster.WrongCodeError{Remaining: 0}, 409, "approve", "replica_request_cancelled", ""},
		{"approve a decided request", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			kubecluster.ErrNotWaiting, 409, "approve", "replica_request_not_waiting", ""},
		{"approve through a spent key", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			kubecluster.ErrKeyNotUsable, 409, "approve", "join_key_not_usable", ""},
		{"reject", http.MethodPost, request + "/actions/reject", `{}`, "", nil, 200, "reject",
			`"state":"rejected"`, ""},
		{"reject with a body", http.MethodPost, request + "/actions/reject", `{"why":"x"}`, "", nil, 400, "",
			"invalid_request", ""},
		{"wrong method", http.MethodPut, cluster, "", "", nil, 405, "", "method_not_allowed", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &kubernetesClusterStub{failure: test.failure}
			options.KubernetesClusters = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			httpRequest := newManagementRequest(t, test.method, kubernetesClustersTestPath(test.path), test.body)
			httpRequest.Header.Del("If-Match")
			if test.ifMatch != "" {
				httpRequest.Header.Set("If-Match", test.ifMatch)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httpRequest)
			body := response.Body.String()
			called := strings.Join(stub.calls, ",")
			if response.Code != test.status || called != test.call || !strings.Contains(body, test.want) ||
				test.absent != "" && strings.Contains(body, test.absent) {
				t.Fatalf("status %d, calls %q; want %d, %q; %s", response.Code, called, test.status, test.call, body)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("a Kubernetes cluster response may be cached")
			}
		})
	}
}

// The handler passes what the person typed to the service, which parses
// it; delete passes the If-Match version.
func TestKubernetesClusterHandlerPassesInputs(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	stub := &kubernetesClusterStub{}
	options.KubernetesClusters = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	approve := newManagementRequest(t, http.MethodPost, kubernetesClustersTestPath("/"+kubernetesTestCluster+
		"/replica-requests/"+kubernetesTestRequest+"/actions/approve"), `{"code":"4kh7i rec2b"}`)
	approve.Header.Del("If-Match")
	handler.ServeHTTP(httptest.NewRecorder(), approve)
	remove := newManagementRequest(t, http.MethodDelete, kubernetesClustersTestPath("/"+kubernetesTestCluster), "")
	remove.Header.Set("If-Match", `"7"`)
	handler.ServeHTTP(httptest.NewRecorder(), remove)
	if len(stub.codes) != 1 || stub.codes[0] != "4kh7i rec2b" ||
		stub.decisions[0].RequestID.String() != kubernetesTestRequest ||
		len(stub.deletions) != 1 || stub.deletions[0].ExpectedVersion != 7 {
		t.Fatalf("codes %v, decisions %+v, deletions %+v", stub.codes, stub.decisions, stub.deletions)
	}
}

func TestKubernetesClustersUnavailableWithoutManager(t *testing.T) {
	t.Parallel()
	handler, err := NewManagementHandler(validManagementHandlerOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodGet, kubernetesClustersTestPath(""), "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; %s", response.Code, response.Body)
	}
}

func TestClassifyKubernetesClusterError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		kubecluster.ErrForbidden:                  "permission_denied",
		kubecluster.ErrNotFound:                   "kubernetes_cluster_not_found",
		kubecluster.ErrConflict:                   "kubernetes_cluster_conflict",
		kubecluster.ErrLimitReached:               "kubernetes_cluster_limit",
		kubecluster.ErrNotWaiting:                 "replica_request_not_waiting",
		kubecluster.ErrKeyNotUsable:               "join_key_not_usable",
		kubecluster.ErrJoinAgain:                  "replica_must_rejoin",
		kubecluster.ErrSigningMismatch:            "replica_signing_mismatch",
		kubecluster.ErrPodHeld:                    "replica_pod_held",
		&kubecluster.WrongCodeError{Remaining: 2}: "join_code_wrong",
		&kubecluster.WrongCodeError{Remaining: 0}: "replica_request_cancelled",
		kubecluster.ErrInvalid:                    "invalid_request",
		errors.New("database is down"):            "temporarily_unavailable",
	} {
		if got := classifyKubernetesClusterError(err).Code; got != code {
			t.Errorf("%v: code = %q, want %q", err, got, code)
		}
	}
}

// A caller who may only read the Network sees the cluster and its replicas,
// and is refused its keys and requests alike, listed or one by one.
func TestKubernetesClusterReadOnlyCaller(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	for path, status := range map[string]int{
		cluster:                200,
		cluster + "/join-keys": 403,
		cluster + "/join-keys/" + kubernetesTestKey:            403,
		cluster + "/replica-requests":                          403,
		cluster + "/replica-requests/" + kubernetesTestRequest: 403,
	} {
		options := validManagementHandlerOptions(t)
		options.KubernetesClusters = &kubernetesClusterStub{readOnly: true}
		handler, err := NewManagementHandler(options)
		if err != nil {
			t.Fatal(err)
		}
		request := newManagementRequest(t, http.MethodGet, kubernetesClustersTestPath(path), "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Errorf("GET %s = %d, want %d; %s", path, response.Code, status, response.Body)
		}
		if status == 200 && (!strings.Contains(response.Body.String(), `"join_keys":null`) ||
			!strings.Contains(response.Body.String(), `"key_warnings":null`)) {
			t.Errorf("GET %s showed keys to a reader: %s", path, response.Body)
		}
	}
}

// A wrong method names the methods the path takes; delete needs If-Match.
func TestKubernetesClusterMethodsAndPreconditions(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	for path, allow := range map[string]string{
		"":                     "GET, POST",
		cluster:                "GET, DELETE",
		cluster + "/join-keys": "GET, POST",
		cluster + "/replica-requests/" + kubernetesTestRequest + "/actions/approve": "POST",
	} {
		options := validManagementHandlerOptions(t)
		options.KubernetesClusters = &kubernetesClusterStub{}
		handler, err := NewManagementHandler(options)
		if err != nil {
			t.Fatal(err)
		}
		request := newManagementRequest(t, http.MethodPut, kubernetesClustersTestPath(path), "{}")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != allow {
			t.Errorf("PUT %q = %d, Allow %q; want 405, %q", path, response.Code, response.Header().Get("Allow"), allow)
		}
	}
	options := validManagementHandlerOptions(t)
	stub := &kubernetesClusterStub{}
	options.KubernetesClusters = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodDelete, kubernetesClustersTestPath(cluster), "")
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired || len(stub.calls) != 0 {
		t.Fatalf("delete without If-Match = %d, calls %v", response.Code, stub.calls)
	}
}

func kubernetesTestDevice() node.ID {
	id, _ := node.ParseID("01890f00-0000-7000-8000-000000000b04")
	return id
}

// An administrator's read sums the gateways' key warnings.
func TestKubernetesClusterReadShowsKeyWarnings(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	options.KubernetesClusters = &kubernetesClusterStub{}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet,
		kubernetesClustersTestPath("/"+kubernetesTestCluster), ""))
	want := `"key_warnings":{"devices":[{"device_id":"01890f00-0000-7000-8000-000000000b04","hostname":"prod-0",` +
		`"count_24h":1,"count_7d":3,"last_at":"2026-10-26T09:00:00Z","last_reason":"retired_machine_key",` +
		`"key_state":"rotated"}],"truncated":false}`
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
		t.Fatalf("read = %d; %s", response.Code, response.Body)
	}
}

// The signing read shows the trust, the replicas' pods and, to those who
// manage or approve the cluster, the waiting requests against the trust and
// the refused rotation tokens.
func TestKubernetesClusterSigningRead(t *testing.T) {
	t.Parallel()
	thumbprint := func(b byte) string { return fmt.Sprintf("%02x%062x", b, 0) }
	for _, readOnly := range []bool{false, true} {
		options := validManagementHandlerOptions(t)
		options.KubernetesClusters = &kubernetesClusterStub{readOnly: readOnly}
		handler, err := NewManagementHandler(options)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet,
			kubernetesClustersTestPath("/"+kubernetesTestCluster+"/signing"), ""))
		body := response.Body.String()
		wants := []string{
			`"cluster_id":"` + kubernetesTestCluster + `"`,
			`"trust":{"issuer":"https://kubernetes.default.svc.cluster.local","key_thumbprints":["` +
				thumbprint(0xab) + `"],` +
				`"keys":[],"namespace":"mt-kube-k1","service_account":"meshgw","statefulset":"meshgw",` +
				`"version":1,"source":"replica_approval","set_at":"2026-10-27T10:55:00Z","set_by":null}`,
			`"replicas":[{"device_id":"01890f00-0000-7000-8000-000000000b04","pod_name":"meshgw-0",` +
				`"last_token_rotation_at":"2026-10-27T11:14:22Z"},{"device_id":` +
				`"01890f00-0000-7000-8000-000000000b04","pod_name":"meshgw-1","last_token_rotation_at":null}]`,
		}
		if readOnly {
			wants = append(wants, `"replica_requests":null`, `"replica_requests_truncated":false`,
				`"token_warnings":null`)
		} else {
			// The trust matches, but an active replica holds the pod.
			wants = append(wants, `"pod_name":"meshgw-0","join_key_thumbprint":"`+thumbprint(0xab)+
				`","trust_state":"pod_held"}`, `"replica_requests_truncated":true`)
			wants = append(wants,
				`"replica_requests":[{"request_id":"`+kubernetesTestRequest+`","code_version":2,`+
					`"issuer":"https://kubernetes.default.svc.cluster.local","namespace":"mt-kube-k1",`+
					`"service_account":"meshgw","statefulset":"meshgw","pod_name":"meshgw-1",`+
					`"join_key_thumbprint":"`+thumbprint(0xcd)+`","trust_state":"differs_from_trust"}`,
				`"token_warnings":{"devices":[{"device_id":"01890f00-0000-7000-8000-000000000b04",`+
					`"hostname":"prod-0","count_24h":1,"count_7d":2,"last_at":"2026-10-27T11:14:22Z",`+
					`"last_reason":"token_missing","key_state":"current"}],"truncated":false}`)
		}
		for _, want := range wants {
			if response.Code != http.StatusOK || !strings.Contains(body, want) {
				t.Fatalf("read-only %t: %d; %s\nwant %s", readOnly, response.Code, body, want)
			}
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
		}
	}
}

// kindSigningJWKS is the JWKS kind meshgw-a served on 2026-10-27.
const kindSigningJWKS = `{"keys":[{"use":"sig","kty":"RSA","kid":"W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE","alg":"RS256","n":"ulb6f8XOFK8q2EKPjPXlwDQuMhPTiee6zlEDZu0twbQecr0w7uG6Vqghhovln3lwCtJdM_eHsWfgmd6I-HdaFUv738BlNvEZXanR9d5mSBmnIDtIUTpwrNOVTuskzBOMceJf86g7QwfL_ixA8xaavgt27B5dqZJcM34ORUy6O2qcm18keFqKhMoQ_FPnFS1xZmEPTw3VzBLpOAaI6sTh0-LBTtszztX-F6GYSw3bZenJUVQ9CHAPr4AtJRrRA0lpZj__gCz9CpajdNfJY712HzBv6tMb8ElqO3DaEr2ka40yqIug9wkMmlLg85MrMhtOZViuZq0hf_SAPFipqjVQKw","e":"AQAB"}]}`

func pastedTrustBody(jwks string) string {
	return `{"issuer":"https://kubernetes.default.svc.cluster.local","jwks":` + jwks +
		`,"namespace":"mt-kube-k1","service_account":"meshgw","statefulset":"meshgw",` +
		`"reason":"kind rotated its signing key"}`
}

// An administrator pastes the cluster's signing keys under the trust's
// version ("0" for none); the body is read strictly and a JWKS refusal
// names its rule.
func TestKubernetesSigningTrustReplace(t *testing.T) {
	t.Parallel()
	trustPath := kubernetesClustersTestPath("/" + kubernetesTestCluster + "/signing-trust")
	put := func(t *testing.T, stub *kubernetesClusterStub, ifMatch, body string) *httptest.ResponseRecorder {
		t.Helper()
		options := validManagementHandlerOptions(t)
		options.KubernetesClusters = stub
		handler, err := NewManagementHandler(options)
		if err != nil {
			t.Fatal(err)
		}
		request := newManagementRequest(t, http.MethodPut, trustPath, body)
		request.Header.Del("If-Match")
		if ifMatch != "" {
			request.Header.Set("If-Match", ifMatch)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	stub := &kubernetesClusterStub{}
	response := put(t, stub, `"0"`, pastedTrustBody(kindSigningJWKS))
	body := response.Body.String()
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` ||
		!strings.Contains(body, `"changed":true`) ||
		!strings.Contains(body, `"keys":[{"kid":"W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE",`+
			`"computed_kid":"W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE","thumbprint":"`) ||
		len(stub.replacements) != 1 || stub.replacements[0].ExpectedVersion != 0 ||
		stub.replacements[0].Reason != "kind rotated its signing key" {
		t.Fatalf("PUT = %d %s; %s; %+v", response.Code, response.Header().Get("ETag"), body, stub.replacements)
	}
	for name, test := range map[string]struct {
		ifMatch, body string
		replaceErr    error
		status        int
		code, rule    string
	}{
		"no If-Match": {"", pastedTrustBody(kindSigningJWKS), nil, http.StatusPreconditionRequired,
			"precondition_required", ""},
		"weak If-Match": {`W/"1"`, pastedTrustBody(kindSigningJWKS), nil, http.StatusBadRequest,
			"invalid_request", ""},
		"bad kid": {`"1"`, pastedTrustBody(strings.Replace(kindSigningJWKS, `"kid":"W5g6`, `"kid":"\u0001W5g6`, 1)),
			nil, http.StatusUnprocessableEntity, "signing_keys_invalid", "kid"},
		"no keys": {`"1"`, pastedTrustBody(`{"keys":[]}`), nil, http.StatusUnprocessableEntity,
			"signing_keys_invalid", "no_keys"},
		"jwks a string": {`"1"`, pastedTrustBody(`"{}"`), nil, http.StatusUnprocessableEntity,
			"signing_keys_invalid", "json"},
		"http issuer": {`"1"`, strings.Replace(pastedTrustBody(kindSigningJWKS), "https://", "http://", 1), nil,
			http.StatusUnprocessableEntity, "signing_identity_invalid", ""},
		"no reason": {`"1"`, strings.Replace(pastedTrustBody(kindSigningJWKS),
			`"reason":"kind rotated its signing key"`, `"reason":""`, 1), nil, http.StatusBadRequest,
			"invalid_request", ""},
		"duplicate member": {`"1"`, strings.Replace(pastedTrustBody(kindSigningJWKS), `{"issuer"`,
			`{"Issuer":"https://other.example","issuer"`, 1), nil, http.StatusBadRequest, "invalid_request", ""},
		"unknown member": {`"1"`, strings.Replace(pastedTrustBody(kindSigningJWKS), `{"issuer"`,
			`{"extra":1,"issuer"`, 1), nil, http.StatusBadRequest, "invalid_request", ""},
		"trust changed": {`"1"`, pastedTrustBody(kindSigningJWKS), kubecluster.ErrTrustChanged,
			http.StatusPreconditionFailed, "signing_trust_changed", ""},
		"identity bound": {`"1"`, pastedTrustBody(kindSigningJWKS), kubecluster.ErrIdentityBound,
			http.StatusConflict, "replica_identity_bound", ""},
		"forbidden": {`"1"`, pastedTrustBody(kindSigningJWKS), kubecluster.ErrForbidden,
			http.StatusForbidden, "permission_denied", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stub := &kubernetesClusterStub{replaceErr: test.replaceErr}
			response := put(t, stub, test.ifMatch, test.body)
			var failure struct {
				Error struct {
					Code     string `json:"code"`
					JWKSRule string `json:"jwks_rule"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || response.Code != test.status ||
				failure.Error.Code != test.code || failure.Error.JWKSRule != test.rule {
				t.Fatalf("PUT = %d %s, want %d %s %s", response.Code, response.Body, test.status, test.code, test.rule)
			}
			if test.replaceErr == nil && len(stub.replacements) != 0 {
				t.Fatal("a refused body reached the cluster manager")
			}
		})
	}
}

// The trust's own read carries its version as the ETag ("0" for none).
func TestKubernetesSigningTrustRead(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	options.KubernetesClusters = &kubernetesClusterStub{}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet,
		kubernetesClustersTestPath("/"+kubernetesTestCluster+"/signing-trust"), ""))
	body := response.Body.String()
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` ||
		!strings.Contains(body, `"trust":{"issuer":"https://kubernetes.default.svc.cluster.local"`) ||
		!strings.Contains(body, `"can_replace_trust":false`) {
		t.Fatalf("GET = %d %s %s", response.Code, response.Header().Get("ETag"), body)
	}
}

// A page's token reaches the next page as its cursor; a token of another
// list or cluster is refused, and a reader of the Network alone is
// forbidden (K1d d1a).
func TestKubernetesClusterPages(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	after, _ := publicid.Parse(kubernetesTestKey)
	next := kubecluster.PageCursor{At: time.Date(2026, time.October, 25, 8, 0, 0, 123456000, time.UTC), ID: after}
	stub := &kubernetesClusterStub{next: next}
	options.KubernetesClusters = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	cluster := "/" + kubernetesTestCluster
	get := func(path string) (int, string) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet, kubernetesClustersTestPath(path), ""))
		return response.Code, response.Body.String()
	}
	status, body := get(cluster + "/join-keys?page_size=1")
	var page struct {
		Data struct {
			NextPageToken string `json:"next_page_token"`
		} `json:"data"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &page) != nil || page.Data.NextPageToken == "" {
		t.Fatalf("first page: %d %s", status, body)
	}
	if status, body := get(cluster + "/join-keys?page_size=1&page_token=" + page.Data.NextPageToken); status != 200 {
		t.Fatalf("next page: %d %s", status, body)
	}
	if len(stub.pages) != 2 || stub.pages[0].Limit != 1 || !stub.pages[0].After.IsZero() ||
		!stub.pages[1].After.At.Equal(next.At) || stub.pages[1].After.ID != next.ID {
		t.Fatalf("pages %+v", stub.pages)
	}
	if status, _ := get(cluster + "/replica-requests?page_token=" + page.Data.NextPageToken); status != 404 {
		t.Fatalf("a key token paged the requests: %d", status)
	}
	other := "/01890f00-0000-7000-8000-000000000b09"
	if status, _ := get(other + "/join-keys?page_token=" + page.Data.NextPageToken); status != 404 {
		t.Fatalf("a token paged another cluster: %d", status)
	}
	if status, _ := get(cluster + "/join-keys?page_token=" + page.Data.NextPageToken + "x"); status != 404 {
		t.Fatalf("a changed token was accepted: %d", status)
	}
	if status, body := get(cluster + "/join-keys"); status != 200 || len(stub.pages) != 3 ||
		stub.pages[2].Limit != kubernetesDefaultPageSize {
		t.Fatalf("default page: %d %s %+v", status, body, stub.pages)
	}
	stub.readOnly = true
	for _, path := range []string{"/join-keys", "/join-keys/" + kubernetesTestKey, "/replica-requests",
		"/replica-requests/" + kubernetesTestRequest} {
		if status, _ := get(cluster + path); status != http.StatusForbidden {
			t.Errorf("a Network reader got %s: %d", path, status)
		}
	}
}

// An operations token carries the range and filters: the next page reads
// the same range even when now moved, a token of another cluster is
// refused, and a query that contradicts the token is refused (K1d d1c).
func TestKubernetesOperationPages(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	after, _ := publicid.Parse(kubernetesTestAuditID)
	next := kubecluster.PageCursor{At: time.Date(2026, time.October, 29, 13, 14, 58, 123000000, time.UTC), ID: after}
	stub := &kubernetesClusterStub{next: next, truncated: true}
	options.KubernetesClusters = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	cluster := "/" + kubernetesTestCluster
	get := func(path string) (int, string) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet, kubernetesClustersTestPath(path), ""))
		return response.Code, response.Body.String()
	}
	status, body := get(cluster + "/operations?class=exec&page_size=5")
	var page struct {
		Data struct {
			From, To      string
			Truncated     bool   `json:"scan_truncated"`
			NextPageToken string `json:"next_page_token"`
		} `json:"data"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &page) != nil || page.Data.NextPageToken == "" ||
		!page.Data.Truncated {
		t.Fatalf("first page: %d %s", status, body)
	}
	first := stub.operationQueries[0]
	if first.Class != "exec" || first.Limit != 5 || first.To.Sub(first.From) != kubernetesDefaultOperationRange {
		t.Fatalf("first query %+v", first)
	}
	if status, body := get(cluster + "/operations?page_size=5&page_token=" + page.Data.NextPageToken); status != 200 {
		t.Fatalf("next page: %d %s", status, body)
	}
	second := stub.operationQueries[1]
	if !second.From.Equal(first.From) || !second.To.Equal(first.To) || second.Class != "exec" ||
		!second.After.At.Equal(next.At) || second.After.ID != next.ID {
		t.Fatalf("second query %+v, first %+v", second, first)
	}
	for _, path := range []string{
		cluster + "/operations?class=write&page_token=" + page.Data.NextPageToken,
		"/01890f00-0000-7000-8000-000000000b09/operations?page_token=" + page.Data.NextPageToken,
		cluster + "/join-keys?page_token=" + page.Data.NextPageToken,
	} {
		if status, _ := get(path); status != 404 {
			t.Errorf("%s: %d, want 404", path, status)
		}
	}
}
