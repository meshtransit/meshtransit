package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

const explainKubernetesBody = `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
	`"destination_kubernetes_cluster_id":"` + kubernetesTestCluster + `","protocol":"tcp","destination_port":443}`

// A cluster asked about is explained through the replica Core names (its
// active replica of the lowest ordinal), and each path names the groups its
// rule grants (K1d d4c).
func TestManagementHandlerExplainsKubernetesCluster(t *testing.T) {
	t.Parallel()
	replica := explainTestReplica("c03")
	stub := &kubernetesClusterStub{explainReplica: replica}
	var asked []node.ID
	handler := explainKubernetesHandler(t, stub, func(query accessgraph.Query) (accessgraph.Snapshot, error) {
		asked = append(asked, query.DestinationNodeID())
		return explainKubernetesSnapshot(t, query), nil
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newManagementRequest(t, http.MethodPost, validAccessGraphExplainPath(),
		explainKubernetesBody))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	var body explainPolicyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != replica ||
		!slices.Equal(stub.calls, []string{"explain-replica:" + kubernetesTestCluster + ":" + managementNetworkID()}) {
		t.Fatalf("asked %v; calls %v", asked, stub.calls)
	}
	target, paths := body.Data.Target, body.Data.Paths
	if body.Data.Decision != "allow" || target.KubernetesClusterID != kubernetesTestCluster ||
		target.DeviceID != replica.String() || len(paths) != 1 ||
		paths[0].DestinationKubernetesClusterID != kubernetesTestCluster ||
		!slices.Equal(paths[0].KubernetesGroups, []string{"view", "edit"}) {
		t.Fatalf("explained = %+v", body.Data)
	}
}

// A cluster stands alone as the destination; a bad one fails before any read.
func TestManagementHandlerRejectsKubernetesClusterExplainBody(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"with Device": `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
			`"destination_kubernetes_cluster_id":"` + kubernetesTestCluster + `",` +
			`"destination_device_id":"01890f00-0000-7000-8000-000000000302","protocol":"tcp","destination_port":443}`,
		"with address": `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
			`"destination_kubernetes_cluster_id":"` + kubernetesTestCluster + `",` +
			`"destination_address":"10.0.0.1","protocol":"tcp","destination_port":443}`,
		"bad id": `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
			`"destination_kubernetes_cluster_id":"prod","protocol":"tcp","destination_port":443}`,
		"no port": `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
			`"destination_kubernetes_cluster_id":"` + kubernetesTestCluster + `","protocol":"tcp"}`,
	} {
		stub := &kubernetesClusterStub{}
		handler := explainKubernetesHandler(t, stub, func(accessgraph.Query) (accessgraph.Snapshot, error) {
			t.Fatalf("%s: explained", name)
			return accessgraph.Snapshot{}, nil
		})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newManagementRequest(t, http.MethodPost, validAccessGraphExplainPath(), body))
		if response.Code != http.StatusBadRequest || len(stub.calls) != 0 {
			t.Fatalf("%s: status = %d, calls %v", name, response.Code, stub.calls)
		}
	}
}

// With no active replica, a cluster unknown or one the caller cannot read,
// nothing is explained.
func TestManagementHandlerKubernetesClusterExplainFailsClosed(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		failure error
		status  int
		code    string
	}{
		"no active replica": {kubecluster.ErrNoActiveReplica, http.StatusConflict,
			"kubernetes_cluster_no_active_replica"},
		"unknown cluster": {kubecluster.ErrNotFound, http.StatusNotFound, "kubernetes_cluster_not_found"},
		"not a reader":    {kubecluster.ErrForbidden, http.StatusForbidden, "permission_denied"},
	} {
		stub := &kubernetesClusterStub{failure: test.failure}
		handler := explainKubernetesHandler(t, stub, func(accessgraph.Query) (accessgraph.Snapshot, error) {
			t.Fatalf("%s: explained", name)
			return accessgraph.Snapshot{}, nil
		})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, newManagementRequest(t, http.MethodPost, validAccessGraphExplainPath(),
			explainKubernetesBody))
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		if response.Code != test.status || body.Error.Code != test.code || len(stub.calls) != 1 {
			t.Fatalf("%s: status = %d, code %q, calls %v", name, response.Code, body.Error.Code, stub.calls)
		}
	}
}

// A Core without the cluster service cannot answer about a cluster.
func TestManagementHandlerKubernetesClusterExplainWithoutClusters(t *testing.T) {
	t.Parallel()
	handler := explainKubernetesHandler(t, nil, func(accessgraph.Query) (accessgraph.Snapshot, error) {
		t.Fatal("explained")
		return accessgraph.Snapshot{}, nil
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newManagementRequest(t, http.MethodPost, validAccessGraphExplainPath(),
		explainKubernetesBody))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
}

func explainKubernetesHandler(t *testing.T, stub *kubernetesClusterStub,
	read func(accessgraph.Query) (accessgraph.Snapshot, error)) *ManagementHandler {
	t.Helper()
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: managementAccessGraphReaderFunc(func(_ context.Context, _ accountsession.Session,
			query accessgraph.Query) (accessgraph.Snapshot, error) {
			return read(query)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	options := validManagementHandlerOptions(t)
	options.PolicyExplanations = service
	if stub != nil {
		options.KubernetesClusters = stub
	}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func explainTestReplica(suffix string) node.ID {
	replica, _ := node.ParseID("01890f00-0000-7000-8000-000000000" + suffix)
	return replica
}

// explainKubernetesSnapshot answers with one path to the replica asked about
// through the cluster's own Device Group, its rule granting view and edit.
func explainKubernetesSnapshot(t *testing.T, query accessgraph.Query) accessgraph.Snapshot {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	projectionID, err := publication.ParseProjectionID("01890f00-0000-7000-8000-000000000701")
	must(err)
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000501")
	must(err)
	group, err := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	must(err)
	ports, err := policy.NewPortRange(443, 443)
	must(err)
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID, SourceNodeID: query.SourceNodeID(),
		DestinationNodeID: query.DestinationNodeID(), Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{ports}, SelectorKind: accessgraph.SelectorKindDevice,
		DestinationDeviceGroupID: group,
	})
	must(err)
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	must(err)
	hash, err := publication.NewSemanticHash(sha256.Sum256([]byte("kubernetes explain fixture")))
	must(err)
	snapshot, err := accessgraph.NewSnapshot(accessgraph.SnapshotParams{
		Scope: query.Scope(), NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9, PolicyRevision: 6,
		DNSRevision: 2, RouteRevision: 2, SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: releaseID, CompilerFormatVersion: 3, SemanticHash: hash,
		TargetNodeID: query.DestinationNodeID(), Paths: []accessgraph.Path{path},
		Source:     managementAccessGraphParticipant(t, "poc-02"),
		TargetKind: accessgraph.TargetKindDevice, Target: managementAccessGraphParticipant(t, "prod-1"),
	})
	must(err)
	cluster, err := kubecluster.ParseID(kubernetesTestCluster)
	must(err)
	name, err := kubecluster.ParseName("prod")
	must(err)
	snapshot, err = snapshot.WithKubernetesClusters([]kubecluster.PolicyGroup{{
		ClusterID: cluster, Name: name, GroupID: group}})
	must(err)
	snapshot, err = snapshot.WithKubernetesGroups(map[policy.RuleID][]string{ruleID: {"view", "edit"}},
		map[policy.RuleID]kubecluster.ID{ruleID: cluster})
	must(err)
	return snapshot
}
