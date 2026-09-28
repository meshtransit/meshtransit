package accessgraph

import "errors"

var (
	// ErrInvalidRevisionVector reports incomplete or causally inconsistent authority revisions.
	ErrInvalidRevisionVector = errors.New("access graph: invalid revision vector")
)

// RevisionVectorParams contains every authority revision that can affect an
// Access Graph result in one Network.
type RevisionVectorParams struct {
	NetworkRevision     int64
	InventoryRevision   int64
	GroupRevision       int64
	PolicyRevision      int64
	DNSRevision         int64
	RouteRevision       int64
	SharingRevision     int64
	IsolationGeneration int64
}

// RevisionVector binds an Access Graph result to one complete authority state.
type RevisionVector struct {
	networkRevision     int64
	inventoryRevision   int64
	groupRevision       int64
	policyRevision      int64
	dnsRevision         int64
	routeRevision       int64
	sharingRevision     int64
	isolationGeneration int64
}

// NewRevisionVector validates one complete authority vector.
func NewRevisionVector(params RevisionVectorParams) (RevisionVector, error) {
	vector := RevisionVector{
		networkRevision: params.NetworkRevision, inventoryRevision: params.InventoryRevision,
		groupRevision: params.GroupRevision, policyRevision: params.PolicyRevision,
		dnsRevision: params.DNSRevision, routeRevision: params.RouteRevision,
		sharingRevision: params.SharingRevision, isolationGeneration: params.IsolationGeneration,
	}
	if !vector.IsValid() {
		return RevisionVector{}, ErrInvalidRevisionVector
	}
	return vector, nil
}

// NetworkRevision returns the aggregate client-visible revision.
func (vector RevisionVector) NetworkRevision() int64 { return vector.networkRevision }

// InventoryRevision returns the Resource collection revision.
func (vector RevisionVector) InventoryRevision() int64 { return vector.inventoryRevision }

// GroupRevision returns the Resource Group collection revision.
func (vector RevisionVector) GroupRevision() int64 { return vector.groupRevision }

// PolicyRevision returns the packet-policy authority revision.
func (vector RevisionVector) PolicyRevision() int64 { return vector.policyRevision }

// DNSRevision returns the DNS authority revision.
func (vector RevisionVector) DNSRevision() int64 { return vector.dnsRevision }

// RouteRevision returns the route authority revision.
func (vector RevisionVector) RouteRevision() int64 { return vector.routeRevision }

// SharingRevision returns the sharing authority revision.
func (vector RevisionVector) SharingRevision() int64 { return vector.sharingRevision }

// IsolationGeneration returns the fail-closed isolation authority generation.
func (vector RevisionVector) IsolationGeneration() int64 { return vector.isolationGeneration }

// IsValid reports whether every subsystem revision can belong to the aggregate revision.
func (vector RevisionVector) IsValid() bool {
	return vector.networkRevision > 0 && vector.inventoryRevision > 0 &&
		vector.groupRevision > 0 && vector.policyRevision > 0 && vector.dnsRevision > 0 &&
		vector.routeRevision > 0 && vector.sharingRevision > 0 &&
		vector.isolationGeneration > 0 && vector.networkRevision >= vector.inventoryRevision &&
		vector.networkRevision >= vector.groupRevision &&
		vector.networkRevision >= vector.policyRevision && vector.networkRevision >= vector.dnsRevision &&
		vector.networkRevision >= vector.routeRevision &&
		vector.networkRevision >= vector.sharingRevision
}

// Equal reports exact revision-vector equality.
func (vector RevisionVector) Equal(other RevisionVector) bool {
	return vector.IsValid() && other.IsValid() && vector == other
}

// NextPolicy returns the expected vector after exactly one policy publication.
func (vector RevisionVector) NextPolicy() (RevisionVector, error) {
	const maximumInt64 = int64(^uint64(0) >> 1)
	if !vector.IsValid() || vector.networkRevision == maximumInt64 ||
		vector.policyRevision == maximumInt64 {
		return RevisionVector{}, ErrInvalidRevisionVector
	}
	vector.networkRevision++
	vector.policyRevision++
	if !vector.IsValid() {
		return RevisionVector{}, ErrInvalidRevisionVector
	}
	return vector, nil
}
