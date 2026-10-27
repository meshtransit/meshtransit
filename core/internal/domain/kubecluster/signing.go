package kubecluster

import (
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// TrustSource is how a cluster's signing trust was set.
type TrustSource string

// Trust sources.
const (
	// TrustFromReplicaApproval: the first approved replica's signing keys.
	TrustFromReplicaApproval TrustSource = "replica_approval"
	// TrustFromAdminPaste: keys an administrator pasted (K1.1b).
	TrustFromAdminPaste TrustSource = "admin_paste"
)

// IsKnown reports one of the sources above.
func (source TrustSource) IsKnown() bool {
	return source == TrustFromReplicaApproval || source == TrustFromAdminPaste
}

// SigningTrust is a cluster's ServiceAccount signing trust (K1.1 design
// §5): the issuer and keys its gateways' pod tokens must be signed with,
// and the namespace, ServiceAccount and StatefulSet they must name.
type SigningTrust struct {
	Issuer         string
	KeyThumbprints [][32]byte
	// Keys names each key; empty from a read that carries no JWKS.
	Keys           []TrustKey
	Namespace      string
	ServiceAccount string
	StatefulSet    string
	Version        int64
	Source         TrustSource
	SetAt          time.Time
	// SetBy is who set the trust, for those who manage or approve the
	// cluster; zero otherwise.
	SetBy publicid.ID
}

// RequestTrustState is how a waiting request's signing material stands
// against its cluster's trust, as approving it would find.
type RequestTrustState string

// Request trust states.
const (
	// RequestSetsTrust: the cluster has no trust; approving sets it.
	RequestSetsTrust RequestTrustState = "sets_trust"
	// RequestMatchesTrust: approving keeps the trust.
	RequestMatchesTrust RequestTrustState = "matches_trust"
	// RequestDiffersFromTrust: approving is refused.
	RequestDiffersFromTrust RequestTrustState = "differs_from_trust"
	// RequestMustJoinAgain: opened without signing material, before K1.1;
	// approving cancels it and the replica joins again.
	RequestMustJoinAgain RequestTrustState = "must_join_again"
	// RequestPodHeld: an active replica already holds the request's pod;
	// approving is refused until that Device is revoked.
	RequestPodHeld RequestTrustState = "pod_held"
)

// RequestSigning is the signing material a pending or approved replica
// request was opened with. CodeVersion 1 has none.
type RequestSigning struct {
	RequestID         RequestID
	CodeVersion       int
	Issuer            string
	Namespace         string
	ServiceAccount    string
	StatefulSet       string
	PodName           string
	JoinKeyThumbprint [32]byte
}

// State compares the request with trust, nil when the cluster has none,
// as approving it does.
func (request RequestSigning) State(trust *SigningTrust) RequestTrustState {
	switch {
	case request.CodeVersion != 2:
		return RequestMustJoinAgain
	case trust == nil:
		return RequestSetsTrust
	case trust.Issuer != request.Issuer || trust.Namespace != request.Namespace ||
		trust.ServiceAccount != request.ServiceAccount || trust.StatefulSet != request.StatefulSet ||
		!slices.Contains(trust.KeyThumbprints, request.JoinKeyThumbprint):
		return RequestDiffersFromTrust
	}
	return RequestMatchesTrust
}

// ReplicaSigning is an active gateway Device of the cluster with the pod
// its join named. LastTokenRotation is when it last rotated a key, each
// time with a valid pod token; zero when it has not since it joined.
type ReplicaSigning struct {
	DeviceID          node.ID
	PodName           string
	LastTokenRotation time.Time
}

// MaximumSigningRequests bounds the waiting requests a signing read lists.
const MaximumSigningRequests = 64

// Signing is a cluster's signing read (K1.1 design §8.4, §9). Requests and
// TokenWarnings are nil for those who neither manage nor approve the
// cluster; RequestsTruncated says more requests wait than were listed.
// Replicas are the active gateway Devices, each the holder of its pod.
type Signing struct {
	// CanReplaceTrust: the caller may replace the trust (K1.1b).
	CanReplaceTrust bool
	// UnknownKeyIDs are the kids the cluster signed tokens with that the
	// trust lacks, since it was set; nil for readers.
	UnknownKeyIDs     []string
	Trust             *SigningTrust
	Replicas          []ReplicaSigning
	Requests          []RequestSigning
	RequestsTruncated bool
	TokenWarnings     *KeyWarnings
}

// StateOf is how approving request would end, as far as the read shows: its
// signing material against the trust first, then its pod against the
// active replicas. An approval in progress for the same pod also holds it;
// the read does not show that.
func (signing Signing) StateOf(request RequestSigning) RequestTrustState {
	state := request.State(signing.Trust)
	if state != RequestSetsTrust && state != RequestMatchesTrust {
		return state
	}
	for _, replica := range signing.Replicas {
		if replica.PodName == request.PodName {
			return RequestPodHeld
		}
	}
	return state
}
