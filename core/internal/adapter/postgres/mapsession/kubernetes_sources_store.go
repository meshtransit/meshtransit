package mapsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/shared/kubeprofile"
)

const (
	kubernetesSourcesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_kubernetes_sources_v1(integer)'), 'EXECUTE'), FALSE)`
	loadKubernetesRuleGroupsSQL = `SELECT access_rule_public_id::TEXT, kubernetes_groups
FROM mesh_ops.load_map_network_kubernetes_rule_groups_v1($1::BIGINT)`
	kubernetesProfilesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_kubernetes_profiles_v1(bigint)'), 'EXECUTE'), FALSE)`
	loadKubernetesRuleAccessSQL = `SELECT access_rule_public_id::TEXT, kubernetes_groups, profile_public_id::TEXT,
    profile_hash, namespaces, cluster_part, mode, report_until
FROM mesh_ops.load_map_network_kubernetes_rule_access_v1($1::BIGINT)`
	loadKubernetesProfilesSQL = `SELECT profile_public_id::TEXT, content_hash, name, rules::TEXT
FROM mesh_ops.load_map_network_kubernetes_profiles_v1($1::BIGINT)`
	kubernetesContactsGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_kubernetes_contacts_v1()'), 'EXECUTE'), FALSE)`
	loadKubernetesContactsSQL = `SELECT cluster_name, access_contact
FROM mesh_ops.load_map_network_kubernetes_contacts_v1()`
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

// kubernetesReaders are the Kubernetes readers an inventory read may run:
// sources (schema 237) and access profiles (schema 260).
type kubernetesReaders struct{ sources, profiles bool }

// readsKubernetesProfiles reports whether this role may run the schema 260
// readers; once granted it is not probed again. Without them a rule that
// applies a profile grants nothing (the reader of schema 258 leaves it out).
func (store *Store) readsKubernetesProfiles(ctx context.Context, transaction databaseTransaction) (bool, error) {
	if store.kubernetesProfilesGranted.Load() {
		return true, nil
	}
	granted, err := functionGranted(ctx, transaction, kubernetesProfilesGrantedSQL)
	if err != nil {
		return false, errors.Join(ErrLoadSnapshot, fmt.Errorf("check Kubernetes profile reader: %w", err))
	}
	if granted {
		store.kubernetesProfilesGranted.Store(true)
	}
	return granted, nil
}

// readKubernetesPolicy sets the Kubernetes groups of params' rules, with
// their profiles and the release's profiles when profiles (K2), and the
// Network's Kubernetes sources, read in the transaction of the rest of the
// policy (K1a3b).
func readKubernetesPolicy(ctx context.Context, transaction databaseTransaction, revision int64,
	params *appmapsession.NetworkPolicyParams, profiles bool) error {
	var groups map[policy.RuleID]kubernetesRuleRead
	var err error
	if profiles {
		groups, err = readKubernetesRuleAccess(ctx, transaction, revision)
		if err == nil {
			params.KubernetesProfiles, err = readKubernetesProfiles(ctx, transaction, revision)
		}
	} else {
		groups, err = readKubernetesRuleGroups(ctx, transaction, revision)
	}
	if err != nil {
		return err
	}
	named := 0
	for index, rule := range params.Rules {
		if read, found := groups[rule.ID]; found {
			params.Rules[index].KubernetesGroups, params.Rules[index].KubernetesAccess = read.groups, read.access
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

// kubernetesRuleRead is one rule's groups and profile as read.
type kubernetesRuleRead struct {
	groups []string
	access *appmapsession.KubernetesRuleAccess
}

func readKubernetesRuleGroups(ctx context.Context, transaction databaseTransaction,
	revision int64) (map[policy.RuleID]kubernetesRuleRead, error) {
	rows, err := transaction.Query(ctx, loadKubernetesRuleGroupsSQL, revision)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read Kubernetes rule groups: %w", nonNil(err)))
	}
	defer rows.Close()
	groups := make(map[policy.RuleID]kubernetesRuleRead)
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
		groups[id] = kubernetesRuleRead{groups: ruleGroups}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes rule groups: %w", err))
	}
	return groups, nil
}

// readKubernetesRuleAccess reads every rule to a cluster that names groups,
// with its profile when it applies one; the scope hash is computed here,
// once per rule, and NewNetworkPolicy checks the rest.
func readKubernetesRuleAccess(ctx context.Context, transaction databaseTransaction,
	revision int64) (map[policy.RuleID]kubernetesRuleRead, error) {
	rows, err := transaction.Query(ctx, loadKubernetesRuleAccessSQL, revision)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read Kubernetes rule access: %w", nonNil(err)))
	}
	defer rows.Close()
	read := make(map[policy.RuleID]kubernetesRuleRead)
	for rows.Next() {
		if len(read) == maximumNetworkPolicyRules {
			return nil, ErrSnapshotEvidence
		}
		var text string
		var ruleGroups, namespaces []string
		var profileID, mode *string
		var profileHash []byte
		var clusterPart *bool
		var reportUntil *time.Time
		if err := rows.Scan(&text, &ruleGroups, &profileID, &profileHash, &namespaces, &clusterPart, &mode,
			&reportUntil); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan Kubernetes rule access: %w", err))
		}
		id, err := policy.ParseRuleID(text)
		if _, duplicate := read[id]; err != nil || duplicate || len(ruleGroups) == 0 {
			return nil, ErrSnapshotEvidence
		}
		entry := kubernetesRuleRead{groups: ruleGroups}
		if profileID == nil && (profileHash != nil || namespaces != nil || clusterPart != nil || mode != nil ||
			reportUntil != nil) {
			return nil, ErrSnapshotEvidence // half a profile is none (review d3 L3)
		}
		if profileID != nil {
			access, ok := decodeKubernetesRuleAccess(profileHash, namespaces, clusterPart, mode, reportUntil)
			if !ok {
				return nil, ErrSnapshotEvidence
			}
			entry.access = access
		}
		read[id] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes rule access: %w", err))
	}
	return read, nil
}

// decodeKubernetesRuleAccess reads a rule's profile columns: the content
// hash, namespaces, cluster part, and enforce, or report until a deadline.
func decodeKubernetesRuleAccess(hash []byte, namespaces []string, clusterPart *bool, mode *string,
	reportUntil *time.Time) (*appmapsession.KubernetesRuleAccess, bool) {
	if len(hash) != 32 || clusterPart == nil || mode == nil {
		return nil, false
	}
	access := &appmapsession.KubernetesRuleAccess{ProfileHash: [32]byte(hash), Namespaces: namespaces,
		ClusterPart: *clusterPart}
	switch {
	case *mode == "enforce" && reportUntil == nil:
	case *mode == "report" && reportUntil != nil:
		access.Report, access.ReportUntil = true, reportUntil.UTC()
	default:
		return nil, false
	}
	scope, err := kubeprofile.ScopeHash(access.ProfileHash, namespaces, access.ClusterPart)
	if err != nil {
		return nil, false
	}
	access.ScopeHash = scope
	return access, true
}

// readKubernetesProfiles reads the profiles the release's rules pin, at most
// as many as a release holds; NewNetworkPolicy checks each against its hash.
func readKubernetesProfiles(ctx context.Context, transaction databaseTransaction,
	revision int64) ([]appmapsession.KubernetesProfile, error) {
	rows, err := transaction.Query(ctx, loadKubernetesProfilesSQL, revision)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read Kubernetes profiles: %w", nonNil(err)))
	}
	defer rows.Close()
	profiles := make([]appmapsession.KubernetesProfile, 0, 4)
	for rows.Next() {
		if len(profiles) == maximumKubernetesProfiles {
			return nil, ErrSnapshotEvidence
		}
		var id, name, rules string
		var hash []byte
		if err := rows.Scan(&id, &hash, &name, &rules); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan Kubernetes profile: %w", err))
		}
		var parts struct {
			Namespaced []kubeprofile.Rule `json:"namespaced"`
			Cluster    []kubeprofile.Rule `json:"cluster"`
		}
		if len(hash) != 32 || json.Unmarshal([]byte(rules), &parts) != nil {
			return nil, ErrSnapshotEvidence
		}
		profiles = append(profiles, appmapsession.KubernetesProfile{Hash: [32]byte(hash), ID: id,
			Profile: kubeprofile.Profile{Name: name, Namespaced: parts.Namespaced, Cluster: parts.Cluster}})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes profiles: %w", err))
	}
	return profiles, nil
}

// readKubernetesContacts reads the clusters' access contacts when this role
// may (schema 262); without, none. One out of form is left out: a contact
// is shown only, never authority.
func (store *Store) readKubernetesContacts(ctx context.Context,
	transaction databaseTransaction) (map[kubecluster.Name]string, error) {
	if !store.kubernetesContactsGranted.Load() {
		granted, err := functionGranted(ctx, transaction, kubernetesContactsGrantedSQL)
		if err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("check Kubernetes contact reader: %w", err))
		}
		if !granted {
			return nil, nil
		}
		store.kubernetesContactsGranted.Store(true)
	}
	rows, err := transaction.Query(ctx, loadKubernetesContactsSQL)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read Kubernetes contacts: %w", nonNil(err)))
	}
	defer rows.Close()
	contacts := make(map[kubecluster.Name]string)
	for rows.Next() {
		if len(contacts) == kubecluster.MaximumClustersPerNetwork {
			break // shown only: never fail a map for it (review d4b L5)
		}
		var name, contact string
		if err := rows.Scan(&name, &contact); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan Kubernetes contact: %w", err))
		}
		cluster, err := kubecluster.ParseName(name)
		if err == nil && kubecluster.ValidAccessContact(contact) {
			contacts[cluster] = contact
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate Kubernetes contacts: %w", err))
	}
	return contacts, nil
}

// maximumKubernetesProfiles bounds the profiles one release holds.
const maximumKubernetesProfiles = 256

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
// counted when count (a map opened, not each refresh of one). Every map
// carries the Network's clusters' trust (kube.ca1 sessions keep it, §7.11).
func (store *Store) kubernetesView(cached cachedInventory, self node.ID, at time.Time,
	count bool) appmapsession.KubernetesView {
	candidate, listed := cached.inventory.Device(self)
	cluster, gateway := candidate.KubernetesCluster()
	if !listed || !gateway {
		return appmapsession.KubernetesView{}.WithTrust(cached.kubernetesTrust)
	}
	// The cluster's CAs come with the inventory, whatever the access
	// evidence (§7.10).
	return cached.withKubernetesCA(store.kubernetesAccessView(cached, self, cluster, at, count),
		cluster).WithTrust(cached.kubernetesTrust)
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
	access, crowded := cached.policy.KubernetesAccessFor(self, replica, at)
	if count && crowded > 0 {
		store.stats.kubernetesWithheldPeerGrants.Add(uint64(crowded))
	}
	table := cached.policy.KubernetesScopeTableFor(self, replica, at)
	if !table.IsEmpty() {
		table.AccessContact = cached.kubernetesContacts[cluster]
	}
	view, err := appmapsession.NewKubernetesView(access, table)
	if err != nil {
		return withheld(&store.stats.kubernetesWithheldEvidence)
	}
	return view
}
