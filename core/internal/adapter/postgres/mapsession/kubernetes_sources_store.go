package mapsession

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

const (
	kubernetesSourcesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_kubernetes_sources_v1(integer)'), 'EXECUTE'), FALSE)`
	loadKubernetesRuleGroupsSQL = `SELECT access_rule_public_id::TEXT, kubernetes_groups
FROM mesh_ops.load_map_network_kubernetes_rule_groups_v1($1::BIGINT)`
	loadKubernetesSourcesSQL = `SELECT device_id, owner_kind, owner_ref, member_owned, owner_active,
    owner_valid_until, owner_changed_at, forwards
FROM mesh_ops.load_map_network_kubernetes_sources_v1($1::INTEGER)`
)

// kubernetesEvidence says whether an inventory's policy carries what its
// gateways' maps need.
type kubernetesEvidence uint8

const (
	// kubernetesNotRead: the Network has no cluster, or the database lacks
	// schema 237; gateways' maps carry no access.
	kubernetesNotRead kubernetesEvidence = iota
	kubernetesRead
	// kubernetesWithheld: the evidence was read but inconsistent; the policy
	// holds none, and gateways' maps withhold their peers' access.
	kubernetesWithheld
)

// readsKubernetesSources reports whether this role may run the schema 237
// readers; schemas only move forward, so once granted it is not probed
// again. Without them a gateway's map carries no Kubernetes access.
func (store *Store) readsKubernetesSources(ctx context.Context, transaction databaseTransaction) (bool, error) {
	if store.kubernetesSourcesGranted.Load() {
		return true, nil
	}
	granted, err := functionGranted(ctx, transaction, kubernetesSourcesGrantedSQL)
	if err != nil {
		return false, errors.Join(ErrLoadSnapshot, fmt.Errorf("check Kubernetes source reader: %w", err))
	}
	if granted {
		store.kubernetesSourcesGranted.Store(true)
	}
	return granted, nil
}

// readKubernetesPolicy sets the Kubernetes groups of params' rules and the
// Network's Kubernetes sources, read in the transaction of the rest of the
// policy (K1a3b).
func readKubernetesPolicy(ctx context.Context, transaction databaseTransaction, revision int64,
	params *appmapsession.NetworkPolicyParams) error {
	groups, err := readKubernetesRuleGroups(ctx, transaction, revision)
	if err != nil {
		return err
	}
	named := 0
	for index, rule := range params.Rules {
		if ruleGroups, found := groups[rule.ID]; found {
			params.Rules[index].KubernetesGroups = ruleGroups
			named++
		}
	}
	// Every rule naming groups is one of the release's group rules.
	if named != len(groups) {
		return ErrSnapshotEvidence
	}
	sources, err := readKubernetesSources(ctx, transaction)
	if err != nil {
		return err
	}
	params.KubernetesSources = sources
	return nil
}

func readKubernetesRuleGroups(ctx context.Context, transaction databaseTransaction,
	revision int64) (map[policy.RuleID][]string, error) {
	rows, err := transaction.Query(ctx, loadKubernetesRuleGroupsSQL, revision)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read Kubernetes rule groups: %w", nonNil(err)))
	}
	defer rows.Close()
	groups := make(map[policy.RuleID][]string)
	for rows.Next() {
		if len(groups) == maximumNetworkPolicyRules {
			return nil, ErrSnapshotEvidence
		}
		var text string
		var ruleGroups []string
		if err := rows.Scan(&text, &ruleGroups); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan Kubernetes rule groups: %w", err))
		}
		id, err := policy.ParseRuleID(text)
		if _, duplicate := groups[id]; err != nil || duplicate || len(ruleGroups) == 0 {
			return nil, ErrSnapshotEvidence
		}
		groups[id] = ruleGroups
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes rule groups: %w", err))
	}
	return groups, nil
}

var kubernetesOwnerKinds = map[string]appmapsession.KubernetesOwnerKind{
	"member": appmapsession.KubernetesOwnerMember, "tags": appmapsession.KubernetesOwnerTags,
	"workspace": appmapsession.KubernetesOwnerWorkspace,
}

func readKubernetesSources(ctx context.Context, transaction databaseTransaction) (
	[]appmapsession.KubernetesSource, error) {
	rows, err := transaction.Query(ctx, loadKubernetesSourcesSQL, maximumNetworkPolicyDevices+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read Kubernetes sources: %w", nonNil(err)))
	}
	defer rows.Close()
	sources := make([]appmapsession.KubernetesSource, 0, 16)
	for rows.Next() {
		if len(sources) == maximumNetworkPolicyDevices {
			return nil, ErrSnapshotEvidence
		}
		var device int64
		var kind, ref string
		var memberOwned, active, forwards bool
		var validUntil, changedAt *time.Time
		if err := rows.Scan(&device, &kind, &ref, &memberOwned, &active, &validUntil, &changedAt,
			&forwards); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan Kubernetes source: %w", err))
		}
		ownerKind, known := kubernetesOwnerKinds[kind]
		if !known || kind == "tags" && !strings.HasPrefix(ref, "tags:") {
			return nil, ErrSnapshotEvidence
		}
		source := appmapsession.KubernetesSource{Device: device, OwnerKind: ownerKind, OwnerRef: ref,
			MemberOwned: memberOwned, OwnerActive: active, Forwards: forwards}
		if validUntil != nil {
			source.OwnerValidUntil = validUntil.UTC()
		}
		if changedAt != nil {
			source.OwnerChangedAt = changedAt.UTC()
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes sources: %w", err))
	}
	return sources, nil
}

// gatewayRead is what a shared read learned of a Device that is a
// Kubernetes gateway replica: listed by the inventory, and newer, the
// inventory is of a later revision than the Device's own facts.
type gatewayRead struct{ listed, newer bool }

// gatewayListed reports whether the inventory lists the Device as a
// Kubernetes gateway replica.
func (cached cachedInventory) gatewayListed(self node.ID) bool {
	candidate, listed := cached.inventory.Device(self)
	_, gateway := candidate.KubernetesCluster()
	return listed && gateway
}

// kubernetesView computes, for the map of self built from cached at the
// database time at, its peers' Kubernetes access: only a gateway replica's,
// only from the Network policy its packet filter is expanded from, and only
// a rule to its own cluster counts. A gateway whose inventory did not read
// the evidence, or read it inconsistent, gets the zero view (withheld),
// counted when count (a map opened, not each refresh of one).
func (store *Store) kubernetesView(cached cachedInventory, self node.ID, at time.Time,
	count bool) appmapsession.KubernetesView {
	candidate, listed := cached.inventory.Device(self)
	cluster, gateway := candidate.KubernetesCluster()
	if !listed || !gateway {
		return appmapsession.KubernetesView{}
	}
	// The cluster's CAs come with the inventory, whatever the access
	// evidence (§7.10).
	return cached.withKubernetesCA(store.kubernetesAccessView(cached, self, cluster, at, count), cluster)
}

// kubernetesAccessView computes a gateway replica's peers' Kubernetes
// access, as kubernetesView says.
func (store *Store) kubernetesAccessView(cached cachedInventory, self node.ID, cluster kubecluster.Name,
	at time.Time, count bool) appmapsession.KubernetesView {
	withheld := func(counter *atomic.Uint64) appmapsession.KubernetesView {
		if count {
			counter.Add(1)
		}
		return appmapsession.KubernetesView{}
	}
	switch cached.kubernetes {
	case kubernetesRead:
	case kubernetesWithheld:
		return withheld(&store.stats.kubernetesWithheldEvidence)
	default:
		return withheld(&store.stats.kubernetesWithheldUnread)
	}
	replica := func(peer node.ID) bool {
		replica, found := cached.inventory.Device(peer)
		peerCluster, isReplica := replica.KubernetesCluster()
		return found && isReplica && peerCluster == cluster
	}
	view, err := appmapsession.NewKubernetesView(cached.policy.KubernetesAccessFor(self, replica, at))
	if err != nil {
		return withheld(&store.stats.kubernetesWithheldEvidence)
	}
	return view
}
