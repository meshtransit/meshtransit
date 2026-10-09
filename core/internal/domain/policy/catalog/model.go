// Package catalog defines bounded current policy projections for rule authoring.
package catalog

import (
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
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
		// A row names its compiled Device destination except when it selects
		// an Imported Resource, a Device Group or a tag destination.
		named := !imported && !deviceGroup && !tag
		if params.DeviceRulesOnly && !device && !deviceGroup && !tag ||
			device && row.DestinationNodeID != row.Intent.DestinationNodeID() ||
			!named && row.DestinationNodeID.IsValid() || named && !row.DestinationNodeID.IsValid() {
			return Snapshot{}, ErrInvalidSnapshot
		}
	}
	params.Rows = slices.Clone(params.Rows)
	return Snapshot{params: params}, nil
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
