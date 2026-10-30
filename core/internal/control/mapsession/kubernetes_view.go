package mapsession

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
)

// KubernetesView is what a cluster gateway's map says of its peers'
// Kubernetes access (K1a3b, mtcp-v1 §7.8): each peer's grants and owner,
// computed from the Network policy the map's packet filter was expanded
// from, and when that access next changes beyond the grants' own deadlines.
// The zero value carries none: the map of another Device, of a session
// without gateway.kube.v1, or one whose evidence was not read with the
// policy (withheld, §12.2).
type KubernetesView struct {
	access    map[node.ID]KubernetesAccess
	refreshAt time.Time
	computed  bool
	// scopes is the table of the gateway's cluster (K2, mtcp-v1 §7.12); only
	// a gateway.kube.v2 session keeps it and the scoped grants
	// (profilesTaken), any other session neither.
	scopes        KubernetesScopeTable
	profilesTaken bool
	// ca is the gateway's cluster's CAs, when caKnown (§7.10): read with
	// the inventory, apart from the access evidence.
	ca      KubernetesCA
	caKnown bool
	// trust is the Network's clusters' trust, for a session that takes it
	// (trustTaken: kube.ca1, §7.11): any node's map, not only a gateway's.
	// It is apart from Equal: a change of it alone reaches the node as a
	// delta, never a snapshot (review d2 H2).
	trust      KubernetesTrust
	trustTaken bool
}

// KubernetesCA is what a gateway's map names of its cluster's CAs (MTCP
// §7.10): the SHA-256 of the active root's DER and of the intermediate that
// signs now, each empty when there is none.
type KubernetesCA struct {
	Root, Signing []byte
}

// Valid reports fingerprints of 32 bytes or none, and no intermediate
// without a root.
func (ca KubernetesCA) Valid() bool {
	return (len(ca.Root) == 0 || len(ca.Root) == 32) && (len(ca.Signing) == 0 || len(ca.Signing) == 32) &&
		(len(ca.Signing) == 0 || len(ca.Root) == 32)
}

// Equal compares two CAs by their fingerprints.
func (ca KubernetesCA) Equal(other KubernetesCA) bool {
	return bytes.Equal(ca.Root, other.Root) && bytes.Equal(ca.Signing, other.Signing)
}

// WithCA returns the view with its gateway's cluster's CAs; an invalid one
// leaves them unknown (the map carries none).
func (view KubernetesView) WithCA(ca KubernetesCA) KubernetesView {
	if !ca.Valid() {
		view.ca, view.caKnown = KubernetesCA{}, false
		return view
	}
	view.ca = KubernetesCA{Root: bytes.Clone(ca.Root), Signing: bytes.Clone(ca.Signing)}
	view.caKnown = true
	return view
}

// WithoutCA returns the view without its cluster's CAs, as a session without
// gateway.cert1 has it.
func (view KubernetesView) WithoutCA() KubernetesView {
	view.ca, view.caKnown = KubernetesCA{}, false
	return view
}

// CA returns the gateway's cluster's CAs; false when the map carries none
// (§7.10 "absent": not read, withheld, or not a gateway.cert1 session).
func (view KubernetesView) CA() (KubernetesCA, bool) {
	return KubernetesCA{Root: bytes.Clone(view.ca.Root), Signing: bytes.Clone(view.ca.Signing)}, view.caKnown
}

// WithTrust returns the view with its Network's clusters' trust.
func (view KubernetesView) WithTrust(trust KubernetesTrust) KubernetesView {
	view.trust = trust
	return view
}

// Trust returns the Network's clusters' trust the view carries; unread
// unless the inventory read it and the session takes it.
func (view KubernetesView) Trust() KubernetesTrust { return view.trust }

// WithTakenTrust returns the view of a session that takes the clusters'
// trust (kube.ca1) with trust, as withKubernetesCapability leaves it.
func (view KubernetesView) WithTakenTrust(trust KubernetesTrust) KubernetesView {
	view.trust, view.trustTaken = trust, true
	return view
}

// TrustTaken reports whether the view's session takes the clusters' trust.
func (view KubernetesView) TrustTaken() bool { return view.trustTaken }

// TrustChanged reports whether two views' sessions differ in the clusters'
// trust they take.
func (view KubernetesView) TrustChanged(other KubernetesView) bool {
	return view.trustTaken != other.trustTaken || !view.trust.Equal(other.trust)
}

// caChanged reports whether two views name other CAs.
func (view KubernetesView) caChanged(other KubernetesView) bool {
	return view.caKnown != other.caKnown || !view.ca.Equal(other.ca)
}

// NewKubernetesView validates and copies one gateway's peer access and its
// cluster's scope table: every peer holds at least one grant across both
// lists, each list sorted and distinct, each grant until a set deadline, a
// scoped grant's scope in the table. The view changes next when its earliest
// grant lapses or a reporting grant starts to enforce: every other end (an
// owner's membership, a selection, a key) bounds the grants it comes with,
// so that is when the gateway's map is rebuilt (K1a3 §13.6).
func NewKubernetesView(access map[node.ID]KubernetesAccess, scopes KubernetesScopeTable) (KubernetesView, error) {
	known := make(map[[32]byte]struct{}, len(scopes.Scopes))
	for _, scope := range scopes.Scopes {
		known[scope.Hash] = struct{}{}
	}
	copied := make(map[node.ID]KubernetesAccess, len(access))
	var refreshAt time.Time
	note := func(at time.Time) {
		if !at.IsZero() && (refreshAt.IsZero() || at.Before(refreshAt)) {
			refreshAt = at
		}
	}
	for peer, entry := range access {
		if !peer.IsValid() || !validKubernetesAccess(entry, known) {
			return KubernetesView{}, ErrInvalidSnapshot
		}
		entry.Grants = slices.Clone(entry.Grants)
		entry.ScopedGrants = slices.Clone(entry.ScopedGrants)
		copied[peer] = entry
		for _, grant := range entry.Grants {
			note(grant.ValidUntil)
		}
		for _, grant := range entry.ScopedGrants {
			note(grant.ValidUntil)
			note(grant.ReportUntil)
		}
	}
	return KubernetesView{access: copied, refreshAt: refreshAt, computed: true,
		scopes: cloneKubernetesScopeTable(scopes)}, nil
}

func validKubernetesAccess(entry KubernetesAccess, scopes map[[32]byte]struct{}) bool {
	if len(entry.Grants)+len(entry.ScopedGrants) == 0 || entry.OwnerKind == KubernetesOwnerUnknown ||
		len(entry.Grants)+len(entry.ScopedGrants) > MaximumKubernetesPeerGrants {
		return false
	}
	for index, grant := range entry.Grants {
		if !kubecluster.ValidKubernetesGroup(grant.Group) || grant.ValidUntil.IsZero() ||
			index > 0 && entry.Grants[index-1].Group >= grant.Group {
			return false
		}
	}
	for index, grant := range entry.ScopedGrants {
		_, known := scopes[grant.Scope]
		if !known || !kubecluster.ValidKubernetesGroup(grant.Group) || grant.ValidUntil.IsZero() ||
			grant.Report == grant.ReportUntil.IsZero() || grant.Report && grant.ReportUntil.After(grant.ValidUntil) ||
			index > 0 && compareKubernetesScopedGrants(entry.ScopedGrants[index-1], grant) >= 0 {
			return false
		}
	}
	return true
}

func cloneKubernetesScopeTable(table KubernetesScopeTable) KubernetesScopeTable {
	return KubernetesScopeTable{Profiles: slices.Clone(table.Profiles), Scopes: slices.Clone(table.Scopes),
		AccessContact: table.AccessContact}
}

// Scopes returns the scope table the map carries (K2); empty for a session
// without gateway.kube.v2 or a cluster whose rules apply no profile.
func (view KubernetesView) Scopes() KubernetesScopeTable {
	return cloneKubernetesScopeTable(view.scopes)
}

// WithoutProfiles returns the view as a session without gateway.kube.v2
// takes it (mtcp-v1 §7.12): no scope table, no scoped grant, no peer that
// held only scoped grants, and a refresh only when a whole grant lapses
// (review d3 H1).
func (view KubernetesView) WithoutProfiles() KubernetesView {
	view.profilesTaken = false
	if view.access == nil && view.scopes.IsEmpty() {
		return view
	}
	stripped := make(map[node.ID]KubernetesAccess, len(view.access))
	var refreshAt time.Time
	for peer, entry := range view.access {
		if len(entry.Grants) == 0 {
			continue
		}
		entry.ScopedGrants = nil
		stripped[peer] = entry
		for _, grant := range entry.Grants {
			if refreshAt.IsZero() || grant.ValidUntil.Before(refreshAt) {
				refreshAt = grant.ValidUntil
			}
		}
	}
	view.access, view.scopes, view.refreshAt = stripped, KubernetesScopeTable{}, refreshAt
	return view
}

// ProfilesTaken reports whether the view's session takes access profiles
// (gateway.kube.v2): a rebuild compares with what it was sent only then.
func (view KubernetesView) ProfilesTaken() bool { return view.profilesTaken }

// Computed reports whether the view was computed for a gateway; false means
// its map carries no Kubernetes access at all.
func (view KubernetesView) Computed() bool { return view.computed }

// For returns one peer's access.
func (view KubernetesView) For(peer node.ID) (KubernetesAccess, bool) {
	entry, found := view.access[peer]
	if !found {
		return KubernetesAccess{}, false
	}
	entry.Grants = slices.Clone(entry.Grants)
	entry.ScopedGrants = slices.Clone(entry.ScopedGrants)
	return entry, true
}

// Len returns how many peers hold access.
func (view KubernetesView) Len() int { return len(view.access) }

// RefreshAt returns when the access next changes: its earliest grant's
// deadline; zero: never.
func (view KubernetesView) RefreshAt() time.Time { return view.refreshAt }

// Equal compares what two views put in a map: whether each carries access,
// and every peer's grants and owner. When they refresh is not part of it.
func (view KubernetesView) Equal(other KubernetesView) bool {
	return view.computed == other.computed && maps.EqualFunc(view.access, other.access, equalKubernetesAccess) &&
		!view.caChanged(other) && view.scopes.Equal(other.scopes)
}

// peerChanged reports whether one peer's access differs between two views.
func (view KubernetesView) peerChanged(other KubernetesView, peer node.ID) bool {
	first, inFirst := view.access[peer]
	second, inSecond := other.access[peer]
	return inFirst != inSecond || inFirst && !equalKubernetesAccess(first, second)
}

func equalKubernetesAccess(first, second KubernetesAccess) bool {
	return first.OwnerKind == second.OwnerKind && first.OwnerRef == second.OwnerRef &&
		first.OwnerChangedAt.Equal(second.OwnerChangedAt) &&
		slices.EqualFunc(first.Grants, second.Grants, func(left, right KubernetesGrant) bool {
			return left.Group == right.Group && left.ValidUntil.Equal(right.ValidUntil)
		}) && equalKubernetesScopedGrants(first.ScopedGrants, second.ScopedGrants)
}

// compareKubernetesGrants orders grants by group.
func compareKubernetesGrants(first, second KubernetesGrant) int {
	return strings.Compare(first.Group, second.Group)
}

// ReadAtLocal returns this host's clock taken before the read the snapshot
// comes from: no later than when its authority was current.
func (snapshot Snapshot) ReadAtLocal() time.Time { return snapshot.readAtLocal }

// Kubernetes returns the map's Kubernetes access of its peers.
func (snapshot Snapshot) Kubernetes() KubernetesView { return snapshot.kubernetes }

// WithKubernetes returns the snapshot with a gateway's peers' Kubernetes
// access, which the store computed from the policy its packet filter was
// expanded from.
func (snapshot Snapshot) WithKubernetes(view KubernetesView) Snapshot {
	snapshot.kubernetes = view
	return snapshot
}

// withKubernetesCapability keeps the Kubernetes access only for a session
// that negotiated gateway.kube.v1 (request.Kubernetes); a map of any other
// session carries none, and neither its peers' owners.
// The cluster's CAs stay only for a session that negotiated gateway.cert1
// (request.KubernetesCA, §7.10), and the clusters' trust only for one that
// negotiated kube.ca1.
func (snapshot Snapshot) withKubernetesCapability(request Request) Snapshot {
	ca, caKnown, trust := snapshot.kubernetes.ca, snapshot.kubernetes.caKnown, snapshot.kubernetes.trust
	if !request.Kubernetes() {
		snapshot.kubernetes = KubernetesView{}
	} else if request.KubernetesProfiles() {
		snapshot.kubernetes.profilesTaken = true
	} else {
		snapshot.kubernetes = snapshot.kubernetes.WithoutProfiles()
	}
	// The clusters' trust stays only for a session that negotiated
	// kube.ca1 (§7.11).
	snapshot.kubernetes.trust, snapshot.kubernetes.trustTaken = KubernetesTrust{}, false
	if request.KubernetesClusters() {
		snapshot.kubernetes.trust, snapshot.kubernetes.trustTaken = trust, true
	}
	if request.KubernetesCA() {
		snapshot.kubernetes.ca, snapshot.kubernetes.caKnown = ca, caKnown
	} else {
		snapshot.kubernetes.ca, snapshot.kubernetes.caKnown = KubernetesCA{}, false
	}
	return snapshot
}

// kubernetesRefreshMargin delays a gateway's refresh past the moment its
// peers' access changes, so the rebuild reads it changed (deadlines come
// early by the read's latency, never late).
const kubernetesRefreshMargin = time.Second

// refreshDeadline is when the stream rebuilds current on its own: its
// earliest projection or key deadline, or, a gateway's, just after its
// peers' Kubernetes access next changes (K1a3 §13.6).
func refreshDeadline(snapshot Snapshot) time.Time {
	deadline := snapshot.ProjectionExpiry()
	if at := snapshot.kubernetes.RefreshAt(); !at.IsZero() {
		if at = at.Add(kubernetesRefreshMargin); at.Before(deadline) {
			deadline = at
		}
	}
	return deadline
}
