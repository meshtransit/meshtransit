// Package catalog defines bounded current policy projections for rule authoring.
package catalog

import (
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// MaximumRows bounds the public projection; incomplete projections cannot be edited.
const MaximumRows = 1000

// ErrInvalidSnapshot indicates incomplete or inconsistent durable evidence.
var ErrInvalidSnapshot = errors.New("invalid active policy snapshot")

// Row preserves the typed selector independently of the compiled local Device path.
type Row struct {
	Intent            compilation.RuleIntent
	DestinationNodeID node.ID
}

// SnapshotParams contains one exact-scope bounded active policy read.
type SnapshotParams struct {
	Scope           network.Scope
	Revision        int64
	SemanticHash    publication.SemanticHash
	RuleCount       int
	DeviceRulesOnly bool
	Rows            []Row
}

// Snapshot owns immutable current policy evidence. It exposes no provider topology.
type Snapshot struct{ params SnapshotParams }

// NewSnapshot validates scope, revision, bounds and typed selectors.
func NewSnapshot(params SnapshotParams) (Snapshot, error) {
	if !params.Scope.IsValid() || params.Revision < 1 || !params.SemanticHash.IsValid() || params.RuleCount < 0 || params.RuleCount > 10000 || len(params.Rows) != min(params.RuleCount, MaximumRows) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	for _, row := range params.Rows {
		if !row.Intent.IsValid() || row.Intent.Scope() != params.Scope {
			return Snapshot{}, ErrInvalidSnapshot
		}
		device := row.Intent.DestinationNodeID().IsValid()
		deviceGroup := row.Intent.DestinationDeviceGroupID().IsValid()
		tag := row.Intent.DestinationTagID().IsValid()
		imported := row.Intent.DestinationImportedResourceID().IsValid()
		siteDestination := row.Intent.DestinationSiteID().IsValid()
		exitDestination := row.Intent.DestinationExitPoolID().IsValid()
		cluster := row.Intent.DestinationKubernetesClusterID().IsValid()
		// A row names its compiled Device destination except when it selects
		// an Imported Resource, a Device Group, a tag, a Site, an Exit Pool or
		// a Kubernetes cluster (a rule to the cluster's own group).
		named := !imported && !deviceGroup && !tag && !siteDestination && !exitDestination && !cluster
		if params.DeviceRulesOnly && !device && !deviceGroup && !tag && !cluster ||
			device && row.DestinationNodeID != row.Intent.DestinationNodeID() ||
			!named && row.DestinationNodeID.IsValid() || named && !row.DestinationNodeID.IsValid() {
			return Snapshot{}, ErrInvalidSnapshot
		}
	}
	params.Rows = slices.Clone(params.Rows)
	return Snapshot{params: params}, nil
}

// WithKubernetesClusters returns the snapshot with every rule to a
// Kubernetes cluster's own Device Group naming the cluster instead. The rows
// keep their order; what the release grants does not change.
func (snapshot Snapshot) WithKubernetesClusters(groups []kubecluster.PolicyGroup) (Snapshot, error) {
	byGroup := make(map[devicegroup.ID]kubecluster.ID, len(groups))
	for _, group := range groups {
		if !group.IsValid() {
			return Snapshot{}, ErrInvalidSnapshot
		}
		byGroup[group.GroupID] = group.ClusterID
	}
	params := snapshot.params
	params.Rows = slices.Clone(snapshot.params.Rows)
	for index, row := range params.Rows {
		cluster, found := byGroup[row.Intent.DestinationDeviceGroupID()]
		if !found {
			continue
		}
		named, err := row.Intent.WithKubernetesCluster(cluster)
		if err != nil {
			return Snapshot{}, ErrInvalidSnapshot
		}
		params.Rows[index].Intent = named
	}
	return NewSnapshot(params)
}

// WithKubernetesGroups returns the snapshot with each rule to a Kubernetes
// cluster naming the groups the release holds for it (K1a3); a rule absent
// from groups names none. Read after WithKubernetesClusters.
func (snapshot Snapshot) WithKubernetesGroups(groups map[policy.RuleID][]string) (Snapshot, error) {
	params := snapshot.params
	params.Rows = slices.Clone(snapshot.params.Rows)
	for index, row := range params.Rows {
		if !row.Intent.DestinationKubernetesClusterID().IsValid() {
			if _, named := groups[row.Intent.ID()]; named {
				return Snapshot{}, ErrInvalidSnapshot
			}
			continue
		}
		named, err := row.Intent.WithKubernetesGroups(groups[row.Intent.ID()])
		if err != nil {
			return Snapshot{}, ErrInvalidSnapshot
		}
		params.Rows[index].Intent = named
	}
	return NewSnapshot(params)
}

// Scope returns the exact authorized Network scope.
func (snapshot Snapshot) Scope() network.Scope { return snapshot.params.Scope }

// Revision returns the current policy revision for strong ETag/CAS.
func (snapshot Snapshot) Revision() int64 { return snapshot.params.Revision }

// SemanticHash returns the active compiler artifact identity.
func (snapshot Snapshot) SemanticHash() publication.SemanticHash { return snapshot.params.SemanticHash }

// RuleCount returns the total number of compiled policy rows.
func (snapshot Snapshot) RuleCount() int { return snapshot.params.RuleCount }

// Complete reports whether every compiled row fits in this projection.
func (snapshot Snapshot) Complete() bool { return snapshot.RuleCount() <= MaximumRows }

// DeviceRulesOnly reports whether every row selects only Devices, groups and
// tags, so appending such intent preserves every selector.
func (snapshot Snapshot) DeviceRulesOnly() bool { return snapshot.params.DeviceRulesOnly }

// Rows returns an independently owned slice of immutable typed intent.
func (snapshot Snapshot) Rows() []Row { return slices.Clone(snapshot.params.Rows) }

// IsValid reports whether this value contains validated evidence.
func (snapshot Snapshot) IsValid() bool {
	return snapshot.Scope().IsValid() && snapshot.Revision() > 0 && snapshot.SemanticHash().IsValid()
}
