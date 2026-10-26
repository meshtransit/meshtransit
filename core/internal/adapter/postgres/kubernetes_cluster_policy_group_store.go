package postgres

import (
	"context"
	"encoding/hex"
	"errors"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	ensureKubernetesClusterPolicyGroupSQL = `SELECT mesh_ops.ensure_kubernetes_cluster_policy_group_v1(` +
		sessionArguments + `,$10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID)::TEXT`
	readKubernetesClusterPolicyGroupsSQL = `SELECT mesh_ops.read_kubernetes_cluster_policy_groups_v1(` +
		sessionArguments + `,$10::UUID,$11::UUID)::TEXT`
)

// KubernetesClusterPolicyGroupStore makes and reads the system Device Group
// of each Kubernetes cluster for policy compilation (K1a2a). It holds no join
// key material.
type KubernetesClusterPolicyGroupStore struct{ store KubernetesClusterStore }

var _ compilation.KubernetesClusterResolver = (*KubernetesClusterPolicyGroupStore)(nil)

// NewKubernetesClusterPolicyGroupStore uses the runtime pool.
func NewKubernetesClusterPolicyGroupStore(pool *Pool, options AccountSessionOptions) (
	*KubernetesClusterPolicyGroupStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, kubecluster.ErrInvalid
	}
	return &KubernetesClusterPolicyGroupStore{
		store: KubernetesClusterStore{database: pool.workspaceRenameDatabase, options: options},
	}, nil
}

// kubernetesPolicyGroupRecord is what ensuring a cluster's group answers;
// the creation fields are present only when the group was made now.
type kubernetesPolicyGroupRecord struct {
	NetworkID        string           `json:"network_id"`
	ClusterID        string           `json:"cluster_id"`
	ClusterName      string           `json:"cluster_name"`
	GroupID          string           `json:"group_id"`
	Created          bool             `json:"created"`
	GroupVersion     int64            `json:"group_version"`
	MembersAdded     int              `json:"members_added"`
	MemberHashBefore string           `json:"member_hash_before"`
	MemberHashAfter  string           `json:"member_hash_after"`
	NetworkRevision  int64            `json:"network_revision"`
	GroupRevision    int64            `json:"group_revision"`
	Permission       string           `json:"permission"`
	Authority        catalogAuthority `json:"authority"`
}

type kubernetesPolicyGroupDocument struct {
	GroupID   string `json:"group_id"`
	ClusterID string `json:"cluster_id"`
	Name      string `json:"name"`
}

func (document kubernetesPolicyGroupDocument) group() (kubecluster.PolicyGroup, error) {
	clusterID, clusterErr := kubecluster.ParseID(document.ClusterID)
	name, nameErr := kubecluster.ParseName(document.Name)
	groupID, groupErr := devicegroup.ParseID(document.GroupID)
	if clusterErr != nil || nameErr != nil || groupErr != nil {
		return kubecluster.PolicyGroup{}, kubecluster.ErrInvalid
	}
	return kubecluster.PolicyGroup{ClusterID: clusterID, Name: name, GroupID: groupID}, nil
}

// ResolvePolicyKubernetesClusters makes the policy group of each given
// cluster that has none, each in its own transaction that records
// kubernetes_cluster.policy_group_created with the member hashes, then
// returns the groups of the Network's active clusters (K1a2a).
func (groups *KubernetesClusterPolicyGroupStore) ResolvePolicyKubernetesClusters(ctx context.Context,
	session accountsession.Session, scope network.Scope, clusters []kubecluster.ID) ([]kubecluster.PolicyGroup, error) {
	if len(clusters) > kubecluster.MaximumClustersPerNetwork {
		return nil, kubecluster.ErrInvalid
	}
	if groups == nil {
		return nil, kubecluster.ErrInvalid
	}
	for _, cluster := range clusters {
		if err := groups.store.ensurePolicyGroup(ctx, session, scope, cluster); err != nil {
			return nil, err
		}
	}
	return groups.store.readPolicyGroups(ctx, session, scope)
}

func (store *KubernetesClusterStore) ensurePolicyGroup(ctx context.Context, session accountsession.Session,
	scope network.Scope, cluster kubecluster.ID) error {
	groupID, err := publicid.New()
	if err != nil {
		return kubecluster.ErrUnavailable
	}
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.ErrUnavailable
	}
	return store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, ensureKubernetesClusterPolicyGroupSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), cluster.String(), groupID.String(),
			changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesPolicyGroupRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.ClusterID != cluster.String() {
			return false, kubecluster.ErrInvalid
		}
		if !record.Created {
			// The group exists: nothing was written.
			return false, nil
		}
		if record.GroupID != groupID.String() || record.NetworkRevision <= 0 || record.GroupVersion <= 0 {
			return false, kubecluster.ErrInvalid
		}
		return true, store.appendPolicyGroupEvent(ctx, tx, session, changeID, record)
	})
}

func (store *KubernetesClusterStore) appendPolicyGroupEvent(ctx context.Context, tx accountSessionTransaction,
	session accountsession.Session, changeID publicid.ID, record kubernetesPolicyGroupRecord) error {
	before, beforeErr := hex.DecodeString(record.MemberHashBefore)
	after, afterErr := hex.DecodeString(record.MemberHashAfter)
	groupID, groupErr := publicid.Parse(record.GroupID)
	if beforeErr != nil || afterErr != nil || groupErr != nil || len(before) != 32 || len(after) != 32 {
		return kubecluster.ErrInvalid
	}
	semantic, err := kubernetesSemanticHash(struct {
		NetworkID  string `json:"network_id"`
		ClusterID  string `json:"cluster_id"`
		GroupID    string `json:"group_id"`
		MemberHash string `json:"member_set_sha256"`
	}{record.NetworkID, record.ClusterID, record.GroupID, record.MemberHashAfter})
	if err != nil {
		return kubecluster.ErrInvalid
	}
	// The correlation of the request is not known here; the change ID binds
	// the event to its transaction.
	correlationID, err := publicid.New()
	if err != nil {
		return kubecluster.ErrUnavailable
	}
	outboxClass := "device_group.changed"
	if record.MembersAdded > 0 {
		// Members joined: the Network revision advanced.
		outboxClass = "network.revision.advanced"
	}
	event := catalogEvent{
		session: session, correlationID: correlationID, changeID: changeID,
		aggregateKind: "device_group", aggregateID: groupID, version: record.GroupVersion,
		networkVersion: record.NetworkRevision, action: "kubernetes_cluster.policy_group_created",
		permission: record.Permission, after: semantic,
		payload: struct {
			NetworkID        string           `json:"network_id"`
			SessionID        string           `json:"session_id"`
			ClusterID        string           `json:"cluster_id"`
			Name             string           `json:"cluster_name"`
			GroupID          string           `json:"group_id"`
			MembersAdded     int              `json:"members_added"`
			MemberHashBefore string           `json:"member_set_sha256_before"`
			MemberHashAfter  string           `json:"member_set_sha256"`
			Authority        catalogAuthority `json:"authority"`
		}{record.NetworkID, session.ID().String(), record.ClusterID, record.ClusterName, record.GroupID,
			record.MembersAdded, record.MemberHashBefore, record.MemberHashAfter, record.Authority},
		outboxClass: outboxClass,
		outbox: struct {
			NetworkID       string `json:"network_id"`
			GroupID         string `json:"group_id"`
			Version         int64  `json:"version"`
			NetworkRevision int64  `json:"network_revision"`
			GroupRevision   int64  `json:"group_revision"`
		}{record.NetworkID, record.GroupID, record.GroupVersion, record.NetworkRevision, record.GroupRevision},
	}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

// readPolicyGroups returns the groups of the Network's active clusters for a
// caller who may read the Network or its policy.
func (store *KubernetesClusterStore) readPolicyGroups(ctx context.Context, session accountsession.Session,
	scope network.Scope) ([]kubecluster.PolicyGroup, error) {
	var groups []kubecluster.PolicyGroup
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesClusterPolicyGroupsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		decoded, err := decodeKubernetesPolicyGroups(encoded, scope)
		groups = decoded
		return false, err
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// decodeKubernetesPolicyGroups reads what read_kubernetes_cluster_policy_groups_v1 answers.
func decodeKubernetesPolicyGroups(encoded string, scope network.Scope) ([]kubecluster.PolicyGroup, error) {
	var read struct {
		NetworkID string                          `json:"network_id"`
		Groups    []kubernetesPolicyGroupDocument `json:"groups"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil ||
		read.NetworkID != scope.NetworkID().String() || read.Groups == nil ||
		len(read.Groups) > kubecluster.MaximumClustersPerNetwork {
		return nil, kubecluster.ErrInvalid
	}
	groups := make([]kubecluster.PolicyGroup, 0, len(read.Groups))
	for _, document := range read.Groups {
		group, err := document.group()
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}
