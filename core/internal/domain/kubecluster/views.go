package kubecluster

import (
	"encoding/json"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/node"
)

// State is a cluster's lifecycle.
type State string

// Cluster states.
const (
	StateActive  State = "active"
	StateDeleted State = "deleted"
)

// ClusterParams rehydrates a Cluster from storage.
type ClusterParams struct {
	ID          ID
	Name        Name
	Description string
	State       State
	Version     int64
	Replicas    int
	CreatedBy   identity.PrincipalID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Cluster is one Kubernetes cluster of a Network.
type Cluster struct {
	params ClusterParams
}

// NewCluster validates stored cluster state.
func NewCluster(params ClusterParams) (Cluster, error) {
	if !params.ID.IsValid() || params.Name == "" || !ValidDescription(params.Description) ||
		(params.State != StateActive && params.State != StateDeleted) || params.Version < 1 ||
		params.Replicas < 0 || !params.CreatedBy.IsValid() || params.CreatedAt.IsZero() ||
		params.UpdatedAt.Before(params.CreatedAt) {
		return Cluster{}, ErrInvalid
	}
	if _, err := ParseName(params.Name.String()); err != nil {
		return Cluster{}, ErrInvalid
	}
	params.CreatedAt, params.UpdatedAt = params.CreatedAt.UTC(), params.UpdatedAt.UTC()
	return Cluster{params: params}, nil
}

// ID returns the cluster's public ID.
func (cluster Cluster) ID() ID { return cluster.params.ID }

// Name returns the cluster's name.
func (cluster Cluster) Name() Name { return cluster.params.Name }

// Description returns what the cluster is, possibly empty.
func (cluster Cluster) Description() string { return cluster.params.Description }

// State returns the cluster's lifecycle state.
func (cluster Cluster) State() State { return cluster.params.State }

// Version returns the cluster's version, for If-Match.
func (cluster Cluster) Version() int64 { return cluster.params.Version }

// Replicas returns how many active gateway Devices the cluster has.
func (cluster Cluster) Replicas() int { return cluster.params.Replicas }

// CreatedBy returns who created the cluster.
func (cluster Cluster) CreatedBy() identity.PrincipalID { return cluster.params.CreatedBy }

// CreatedAt returns when the cluster was created.
func (cluster Cluster) CreatedAt() time.Time { return cluster.params.CreatedAt }

// UpdatedAt returns when the cluster last changed.
func (cluster Cluster) UpdatedAt() time.Time { return cluster.params.UpdatedAt }

// KeyState is a join key's lifecycle as seen now.
type KeyState string

// Join key states.
const (
	KeyActive  KeyState = "active"
	KeyUsed    KeyState = "used"
	KeyExpired KeyState = "expired"
	KeyRevoked KeyState = "revoked"
)

// JoinKeyParams rehydrates a JoinKey from storage.
type JoinKeyParams struct {
	ID        enrollment.CredentialID
	IssuedBy  identity.PrincipalID
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
	Uses      int
	Used      int
	State     KeyState
	Version   int64
}

// JoinKey is one join key of a cluster, without its secret.
type JoinKey struct {
	params JoinKeyParams
}

// NewJoinKey validates stored key state.
func NewJoinKey(params JoinKeyParams) (JoinKey, error) {
	switch params.State {
	case KeyActive, KeyUsed, KeyExpired, KeyRevoked:
	default:
		return JoinKey{}, ErrInvalid
	}
	if !params.ID.IsValid() || !params.IssuedBy.IsValid() || params.CreatedAt.IsZero() ||
		!params.ExpiresAt.After(params.CreatedAt) || params.Uses < 1 || params.Uses > MaximumJoinKeyUses ||
		params.Used < 0 || params.Used > params.Uses || params.Version < 1 ||
		(params.State == KeyRevoked) != !params.RevokedAt.IsZero() {
		return JoinKey{}, ErrInvalid
	}
	params.CreatedAt, params.ExpiresAt = params.CreatedAt.UTC(), params.ExpiresAt.UTC()
	if !params.RevokedAt.IsZero() {
		params.RevokedAt = params.RevokedAt.UTC()
	}
	return JoinKey{params: params}, nil
}

// ID returns the key's public ID.
func (key JoinKey) ID() enrollment.CredentialID { return key.params.ID }

// IssuedBy returns who issued the key.
func (key JoinKey) IssuedBy() identity.PrincipalID { return key.params.IssuedBy }

// CreatedAt returns when the key was issued.
func (key JoinKey) CreatedAt() time.Time { return key.params.CreatedAt }

// ExpiresAt returns when the key stops opening requests.
func (key JoinKey) ExpiresAt() time.Time { return key.params.ExpiresAt }

// RevokedAt returns when the key was revoked, or the zero time.
func (key JoinKey) RevokedAt() time.Time { return key.params.RevokedAt }

// Uses returns how many replicas the key may add.
func (key JoinKey) Uses() int { return key.params.Uses }

// Used returns how many approvals consumed it.
func (key JoinKey) Used() int { return key.params.Used }

// State returns the key's lifecycle state.
func (key JoinKey) State() KeyState { return key.params.State }

// Version returns the key's version.
func (key JoinKey) Version() int64 { return key.params.Version }

// IssuedJoinKey is a new key and its one-time presentation.
type IssuedJoinKey struct {
	Key          JoinKey
	Presentation enrollment.JoinKeyPresentation
}

// ReplicaRequestParams rehydrates a ReplicaRequestView from storage.
type ReplicaRequestParams struct {
	ID                 RequestID
	ClusterID          ID
	KeyID              enrollment.CredentialID
	MachineFingerprint string
	NodeFingerprint    string
	Hostname           string
	// Reported is what the pod says about itself, for display only.
	Reported           json.RawMessage
	Lifecycle          Request
	ApprovedBy         identity.PrincipalID
	ApprovedAt         time.Time
	CompletionDeadline time.Time
	ReservedOrdinal    int
	ReservedHostname   string
	DeviceID           node.ID
	Version            int64
	UpdatedAt          time.Time
}

// ReplicaRequestView is a replica's request as an administrator sees it:
// never its nonce.
type ReplicaRequestView struct {
	params ReplicaRequestParams
}

// NewReplicaRequestView validates a stored request.
func NewReplicaRequestView(params ReplicaRequestParams) (ReplicaRequestView, error) {
	state := params.Lifecycle.State()
	approved := !params.ApprovedAt.IsZero()
	if !params.ID.IsValid() || !params.ClusterID.IsValid() || !params.KeyID.IsValid() ||
		len(params.MachineFingerprint) != 64 || len(params.NodeFingerprint) != 64 ||
		params.Hostname == "" || !state.IsKnown() || params.Version < 1 ||
		approved != params.ApprovedBy.IsValid() || approved == params.CompletionDeadline.IsZero() ||
		(state == RequestApproved || state == RequestCompleted) && !approved ||
		(state == RequestCompleted) != params.DeviceID.IsValid() ||
		params.ReservedOrdinal < 0 || params.ReservedOrdinal > MaximumOrdinal ||
		approved == (params.ReservedHostname == "") || len(params.Reported) > 4096 {
		return ReplicaRequestView{}, ErrInvalid
	}
	params.Reported = append(json.RawMessage(nil), params.Reported...)
	return ReplicaRequestView{params: params}, nil
}

// ID returns the request's public ID.
func (view ReplicaRequestView) ID() RequestID { return view.params.ID }

// ClusterID returns the cluster the replica asks to join.
func (view ReplicaRequestView) ClusterID() ID { return view.params.ClusterID }

// KeyID returns the join key the replica presented.
func (view ReplicaRequestView) KeyID() enrollment.CredentialID { return view.params.KeyID }

// MachineFingerprint returns the hex SHA-256 of the machine key Core saw.
func (view ReplicaRequestView) MachineFingerprint() string { return view.params.MachineFingerprint }

// NodeFingerprint returns the hex SHA-256 of the node key Core saw.
func (view ReplicaRequestView) NodeFingerprint() string { return view.params.NodeFingerprint }

// Hostname returns the name the replica sent, for display.
func (view ReplicaRequestView) Hostname() string { return view.params.Hostname }

// Reported returns a copy of what the pod says about itself: unverified.
func (view ReplicaRequestView) Reported() json.RawMessage {
	return append(json.RawMessage(nil), view.params.Reported...)
}

// Lifecycle returns the request's state, attempts and deadlines.
func (view ReplicaRequestView) Lifecycle() Request { return view.params.Lifecycle }

// Approval returns who approved the request and when it must complete.
func (view ReplicaRequestView) Approval() (identity.PrincipalID, time.Time, time.Time, bool) {
	return view.params.ApprovedBy, view.params.ApprovedAt, view.params.CompletionDeadline,
		!view.params.ApprovedAt.IsZero()
}

// Reservation returns the ordinal and name reserved at approval.
func (view ReplicaRequestView) Reservation() (int, string, bool) {
	return view.params.ReservedOrdinal, view.params.ReservedHostname, view.params.ReservedHostname != ""
}

// DeviceID returns the gateway Device of a completed request.
func (view ReplicaRequestView) DeviceID() (node.ID, bool) {
	return view.params.DeviceID, view.params.DeviceID.IsValid()
}

// Version returns the request's version.
func (view ReplicaRequestView) Version() int64 { return view.params.Version }

// UpdatedAt returns when the request last changed.
func (view ReplicaRequestView) UpdatedAt() time.Time { return view.params.UpdatedAt }

// Replica is one gateway Device of a cluster.
type Replica struct {
	DeviceID  node.ID
	Name      string
	Ordinal   int
	State     string
	CreatedAt time.Time
}

// Detail is one cluster with its replicas and, for administrators who may
// manage or approve, its keys and latest requests.
type Detail struct {
	Cluster  Cluster
	Replicas []Replica
	// Keys and Requests are nil when the caller may only read the Network.
	Keys     []JoinKey
	Requests []ReplicaRequestView
	// KeyWarnings sums the gateways' key events; nil when the caller may only
	// read the Network, or Core read an older cluster document.
	KeyWarnings *KeyWarnings
}
