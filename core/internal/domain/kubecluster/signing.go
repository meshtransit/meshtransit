package kubecluster

import (
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/node"
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
	Namespace      string
	ServiceAccount string
	StatefulSet    string
	Version        int64
	Source         TrustSource
	SetAt          time.Time
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

// ReplicaSigning is a gateway Device of the cluster, not deleted, with the
// pod its join named. LastTokenRotation is when it last rotated a key, each
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
// cluster.
type Signing struct {
	Trust         *SigningTrust
	Replicas      []ReplicaSigning
	Requests      []RequestSigning
	TokenWarnings *KeyWarnings
}
