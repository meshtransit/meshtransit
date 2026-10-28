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
	// ca is the gateway's cluster's CAs, when caKnown (§7.10): read with
	// the inventory, apart from the access evidence.
	ca      KubernetesCA
	caKnown bool
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

// caChanged reports whether two views name other CAs.
func (view KubernetesView) caChanged(other KubernetesView) bool {
	return view.caKnown != other.caKnown || !view.ca.Equal(other.ca)
}

// NewKubernetesView validates and copies one gateway's peer access: every
// peer holds at least one group, sorted and distinct, each until a set
// deadline. The view changes next when its earliest grant lapses: every
// other end (an owner's membership, a selection, a key) bounds the grants it
// comes with, so that is when the gateway's map is rebuilt (K1a3 §13.6).
func NewKubernetesView(access map[node.ID]KubernetesAccess) (KubernetesView, error) {
	copied := make(map[node.ID]KubernetesAccess, len(access))
	var refreshAt time.Time
	for peer, entry := range access {
		if !peer.IsValid() || !validKubernetesAccess(entry) {
			return KubernetesView{}, ErrInvalidSnapshot
		}
		entry.Grants = slices.Clone(entry.Grants)
		copied[peer] = entry
		for _, grant := range entry.Grants {
			if refreshAt.IsZero() || grant.ValidUntil.Before(refreshAt) {
				refreshAt = grant.ValidUntil
			}
		}
	}
	return KubernetesView{access: copied, refreshAt: refreshAt, computed: true}, nil
}

func validKubernetesAccess(entry KubernetesAccess) bool {
	if len(entry.Grants) == 0 || entry.OwnerKind == KubernetesOwnerUnknown {
		return false
	}
	for index, grant := range entry.Grants {
		if !kubecluster.ValidKubernetesGroup(grant.Group) || grant.ValidUntil.IsZero() ||
			index > 0 && entry.Grants[index-1].Group >= grant.Group {
			return false
		}
	}
	return true
}

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
		!view.caChanged(other)
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
		})
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
// (request.KubernetesCA, §7.10).
func (snapshot Snapshot) withKubernetesCapability(request Request) Snapshot {
	ca, caKnown := snapshot.kubernetes.ca, snapshot.kubernetes.caKnown
	if !request.Kubernetes() {
		snapshot.kubernetes = KubernetesView{}
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
