package kubecluster

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

var (
	// ErrForbidden reports a session without the permission in the Network.
	ErrForbidden = errors.New("kubernetes cluster: forbidden")
	// ErrNotFound reports a cluster, key or request unknown in the Network.
	ErrNotFound = errors.New("kubernetes cluster: not found")
	// ErrConflict reports a stale version, a name in use, or a cluster that
	// still has replicas or requests.
	ErrConflict = errors.New("kubernetes cluster: conflict")
	// ErrLimitReached reports a Network, cluster or key at its ceiling.
	ErrLimitReached = errors.New("kubernetes cluster: limit reached")
	// ErrNotWaiting reports a request that can no longer be decided.
	ErrNotWaiting = errors.New("kubernetes cluster: request is not waiting")
	// ErrKeyNotUsable reports a join key revoked, expired or used up; an
	// approval through it cancels the request.
	ErrKeyNotUsable = errors.New("kubernetes cluster: join key is not usable")
	// ErrWrongCode reports a code that does not match the request; see
	// WrongCodeError for the attempts left.
	ErrWrongCode = errors.New("kubernetes cluster: wrong code")
	// ErrUnavailable reports a dependency failure.
	ErrUnavailable = errors.New("kubernetes cluster: unavailable")
)

// WrongCodeError is ErrWrongCode with the attempts left; zero means the
// request was cancelled.
type WrongCodeError struct {
	Remaining int
}

func (err *WrongCodeError) Error() string { return ErrWrongCode.Error() }

// Unwrap lets errors.Is match ErrWrongCode.
func (err *WrongCodeError) Unwrap() error { return ErrWrongCode }

const (
	// MaximumClustersPerNetwork bounds a Network's active clusters.
	MaximumClustersPerNetwork = 64
	// MaximumReplicasPerCluster bounds a cluster's live replicas (ordinals
	// 0 to 63, schema 224).
	MaximumReplicasPerCluster = 64
	// MaximumListedKeys bounds the keys a cluster's detail lists.
	MaximumListedKeys = 50
	// MaximumListedRequests bounds the requests a cluster's detail lists.
	MaximumListedRequests = 50
)

// Creation asks for one cluster.
type Creation struct {
	Session       accountsession.Session
	Scope         network.Scope
	ID            ID
	Name          Name
	Description   string
	CorrelationID publicid.ID
}

// Deletion asks to delete one cluster; a zero ExpectedVersion skips the
// version check.
type Deletion struct {
	Session         accountsession.Session
	Scope           network.Scope
	ClusterID       ID
	ExpectedVersion int64
	CorrelationID   publicid.ID
}

// KeyIssue asks for one join key; Token is the secret Core generated.
type KeyIssue struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	KeyID         enrollment.CredentialID
	Token         enrollment.CredentialToken
	Lifetime      time.Duration
	Uses          int
	CorrelationID publicid.ID
}

// KeyRevocation asks to revoke one join key.
type KeyRevocation struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	KeyID         enrollment.CredentialID
	CorrelationID publicid.ID
}

// DecisionKind is what an administrator decides about a request.
type DecisionKind string

// Decisions.
const (
	DecisionApprove DecisionKind = "approve"
	DecisionReject  DecisionKind = "reject"
)

// Decision is an administrator's approval (with the code typed) or
// rejection of a request.
type Decision struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	RequestID     RequestID
	Kind          DecisionKind
	Code          kubejoin.Code
	CorrelationID publicid.ID
}

// Store persists clusters; PostgreSQL authorizes each call on the database
// clock and every change commits with its audit record. DecideReplicaRequest
// compares an approval's code with the one computed from the request's keys
// in the same transaction that records the outcome.
type Store interface {
	CreateCluster(ctx context.Context, creation Creation) (Cluster, error)
	DeleteCluster(ctx context.Context, deletion Deletion) (Cluster, error)
	ListClusters(ctx context.Context, session accountsession.Session, scope network.Scope) ([]Cluster, error)
	ReadCluster(ctx context.Context, session accountsession.Session, scope network.Scope, id ID) (Detail, error)
	IssueJoinKey(ctx context.Context, issue KeyIssue) (JoinKey, error)
	RevokeJoinKey(ctx context.Context, revocation KeyRevocation) (JoinKey, error)
	DecideReplicaRequest(ctx context.Context, decision Decision) (ReplicaRequestView, error)
}

// Clock reads the host's time; it only refuses sessions that already ended.
type Clock interface {
	Now() time.Time
}

// Secrets creates join key secrets and IDs.
type Secrets interface {
	NewToken() (enrollment.CredentialToken, error)
	NewCredentialID() (enrollment.CredentialID, error)
}

// Service validates cluster requests before PostgreSQL authorizes them.
type Service struct {
	store   Store
	clock   Clock
	secrets Secrets
}

// NewService requires a store, a clock and a secret source.
func NewService(store Store, clock Clock, secrets Secrets) (*Service, error) {
	if store == nil || clock == nil || secrets == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock, secrets: secrets}, nil
}

// admit refuses a session that has already ended on this host's clock. It
// can only deny: the store authorizes the session on the database clock.
func (service *Service) admit(ctx context.Context, session accountsession.Session, scope network.Scope) error {
	if ctx == nil || service == nil || service.store == nil || !scope.IsValid() {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// Create adds a cluster to the Network.
func (service *Service) Create(ctx context.Context, creation Creation) (Cluster, error) {
	if err := service.admit(ctx, creation.Session, creation.Scope); err != nil {
		return Cluster{}, err
	}
	if _, err := ParseName(creation.Name.String()); err != nil || !creation.ID.IsValid() ||
		!ValidDescription(creation.Description) || !creation.CorrelationID.IsValid() {
		return Cluster{}, ErrInvalid
	}
	return service.store.CreateCluster(ctx, creation)
}

// Delete removes a cluster that has no replica or open request left.
func (service *Service) Delete(ctx context.Context, deletion Deletion) (Cluster, error) {
	if err := service.admit(ctx, deletion.Session, deletion.Scope); err != nil {
		return Cluster{}, err
	}
	if !deletion.ClusterID.IsValid() || deletion.ExpectedVersion < 0 || !deletion.CorrelationID.IsValid() {
		return Cluster{}, ErrInvalid
	}
	return service.store.DeleteCluster(ctx, deletion)
}

// List returns the Network's active clusters by name.
func (service *Service) List(ctx context.Context, session accountsession.Session,
	scope network.Scope) ([]Cluster, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return nil, err
	}
	return service.store.ListClusters(ctx, session, scope)
}

// Read returns one cluster's detail.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope,
	id ID) (Detail, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Detail{}, err
	}
	if !id.IsValid() {
		return Detail{}, ErrInvalid
	}
	return service.store.ReadCluster(ctx, session, scope, id)
}

// KeyRequest asks for a join key of a cluster: zero Lifetime means an hour.
type KeyRequest struct {
	Session       accountsession.Session
	Scope         network.Scope
	ClusterID     ID
	Lifetime      time.Duration
	Uses          int
	CorrelationID publicid.ID
}

// IssueJoinKey creates a key and returns it with its one-time presentation.
func (service *Service) IssueJoinKey(ctx context.Context, request KeyRequest) (IssuedJoinKey, error) {
	if err := service.admit(ctx, request.Session, request.Scope); err != nil {
		return IssuedJoinKey{}, err
	}
	lifetime := request.Lifetime
	if lifetime == 0 {
		lifetime = DefaultJoinKeyLifetime
	}
	if !request.ClusterID.IsValid() || !ValidJoinKey(lifetime, request.Uses) || !request.CorrelationID.IsValid() {
		return IssuedJoinKey{}, ErrInvalid
	}
	token, err := service.secrets.NewToken()
	if err != nil {
		return IssuedJoinKey{}, ErrUnavailable
	}
	keyID, err := service.secrets.NewCredentialID()
	if err != nil {
		return IssuedJoinKey{}, ErrUnavailable
	}
	presentation, err := enrollment.NewJoinKeyPresentation(keyID, token)
	if err != nil {
		return IssuedJoinKey{}, ErrUnavailable
	}
	key, err := service.store.IssueJoinKey(ctx, KeyIssue{
		Session: request.Session, Scope: request.Scope, ClusterID: request.ClusterID, KeyID: keyID,
		Token: token, Lifetime: lifetime, Uses: request.Uses, CorrelationID: request.CorrelationID,
	})
	if err != nil {
		return IssuedJoinKey{}, err
	}
	return IssuedJoinKey{Key: key, Presentation: presentation}, nil
}

// RevokeJoinKey ends a key and cancels its waiting and approved requests.
func (service *Service) RevokeJoinKey(ctx context.Context, revocation KeyRevocation) (JoinKey, error) {
	if err := service.admit(ctx, revocation.Session, revocation.Scope); err != nil {
		return JoinKey{}, err
	}
	if !revocation.ClusterID.IsValid() || !revocation.KeyID.IsValid() || !revocation.CorrelationID.IsValid() {
		return JoinKey{}, ErrInvalid
	}
	return service.store.RevokeJoinKey(ctx, revocation)
}

// Approve approves a waiting request with the code the replica printed, as
// typed. A code that is not ten base32 characters is refused before the
// store and is not counted; a wrong one is counted and returns
// *WrongCodeError.
func (service *Service) Approve(ctx context.Context, decision Decision, typed string) (ReplicaRequestView, error) {
	code, err := kubejoin.Parse(typed)
	if err != nil {
		return ReplicaRequestView{}, ErrInvalid
	}
	decision.Kind, decision.Code = DecisionApprove, code
	return service.decide(ctx, decision)
}

// Reject rejects a waiting request.
func (service *Service) Reject(ctx context.Context, decision Decision) (ReplicaRequestView, error) {
	decision.Kind, decision.Code = DecisionReject, kubejoin.Code{}
	return service.decide(ctx, decision)
}

func (service *Service) decide(ctx context.Context, decision Decision) (ReplicaRequestView, error) {
	if err := service.admit(ctx, decision.Session, decision.Scope); err != nil {
		return ReplicaRequestView{}, err
	}
	if !decision.ClusterID.IsValid() || !decision.RequestID.IsValid() || !decision.CorrelationID.IsValid() {
		return ReplicaRequestView{}, ErrInvalid
	}
	return service.store.DecideReplicaRequest(ctx, decision)
}

var (
	// ErrJoinRefused reports a join key that is unknown, of another kind, or
	// whose secret does not match: the replica learns nothing more.
	ErrJoinRefused = errors.New("kubernetes cluster: join key refused")
	// ErrKeysInUse reports a machine key or node key that a Device or
	// another registration already holds.
	ErrKeysInUse = errors.New("kubernetes cluster: keys already in use")
	// ErrQueueFull reports a key with twice its uses already waiting.
	ErrQueueFull = errors.New("kubernetes cluster: too many replicas waiting")
)

// What a pod says about itself is a flat JSON object of strings, bounded so
// that its stored form (JSONB text, a space after each ':' and ',') stays
// under the database's 4 KiB.
const (
	MaximumReportedBytes  = 2048
	MaximumReportedFields = 16
	MaximumReportedKey    = 64
	MaximumReportedValue  = 256
)

// CanonicalReported accepts a flat JSON object of at most
// MaximumReportedFields string values, keys of at most MaximumReportedKey
// bytes and values of at most MaximumReportedValue bytes, and returns it
// compact with sorted keys, at most MaximumReportedBytes. Anything else is
// ErrInvalid.
func CanonicalReported(raw json.RawMessage) (json.RawMessage, error) {
	var fields map[string]string
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil || len(fields) > MaximumReportedFields {
		return nil, ErrInvalid
	}
	for key, value := range fields {
		if key == "" || len(key) > MaximumReportedKey || len(value) > MaximumReportedValue {
			return nil, ErrInvalid
		}
	}
	canonical, err := json.Marshal(fields)
	if err != nil || len(canonical) > MaximumReportedBytes {
		return nil, ErrInvalid
	}
	return canonical, nil
}

// JoinAttempt is a replica's request to join, as its session presents it.
// Core chose RequestID and Nonce; the keys are the session's proven ones.
type JoinAttempt struct {
	Presentation enrollment.JoinKeyPresentation
	MachineKey   node.MachineKey
	NodeKey      node.Key
	Hostname     node.Hostname
	// Reported is what the pod says about itself, display only, in the
	// form CanonicalReported returns.
	Reported  json.RawMessage
	RequestID RequestID
	Nonce     [32]byte
	// Trust is the pod's verified signing material (K1.1): required.
	Trust JoinTrust
}

// IsValid reports whether every field is present and bounded.
func (attempt JoinAttempt) IsValid() bool {
	canonical, err := CanonicalReported(attempt.Reported)
	return err == nil && string(canonical) == string(attempt.Reported) &&
		attempt.Presentation.IsValid() && attempt.MachineKey.IsValid() && attempt.NodeKey.IsValid() &&
		attempt.MachineKey.Bytes() != attempt.NodeKey.Bytes() && attempt.Hostname.IsValid() &&
		attempt.RequestID.IsValid() && attempt.Nonce != ([32]byte{}) && attempt.Trust.IsValid()
}

// JoinTicket is what the replica's session needs to wait for approval: the
// request, the cluster and the nonce its code binds. Created is false when
// the same keys asked again and got their open request back.
type JoinTicket struct {
	Request   ReplicaRequestView
	ClusterID ID
	// Scope is the cluster's Network, where the session completes the
	// request.
	Scope   network.Scope
	Nonce   [32]byte
	Created bool
	// TrustConflict is true when the same keys asked again with other
	// signing material than their request holds: the replica's code cannot
	// match, and its session answers CONFLICT with the request.
	TrustConflict bool
}

// JoinStore opens requests for replicas' sessions: it verifies the key's
// secret against its stored digest in the transaction that opens the
// request and records kubernetes_replica_request.opened.
type JoinStore interface {
	OpenReplicaRequest(ctx context.Context, attempt JoinAttempt) (JoinTicket, error)
}

// SystemSecrets draws join key secrets from the operating system's CSPRNG
// and IDs as UUIDv7.
type SystemSecrets struct{}

// NewToken returns a new 256-bit secret.
func (SystemSecrets) NewToken() (enrollment.CredentialToken, error) {
	return enrollment.GenerateCredentialToken()
}

// NewCredentialID returns a new key ID.
func (SystemSecrets) NewCredentialID() (enrollment.CredentialID, error) {
	id, err := publicid.New()
	if err != nil {
		return enrollment.CredentialID{}, err
	}
	return enrollment.CredentialID(id), nil
}

// NewRequestID returns a new request ID.
func (SystemSecrets) NewRequestID() (RequestID, error) {
	id, err := publicid.New()
	if err != nil {
		return RequestID{}, err
	}
	return RequestID(id), nil
}

// NewRequestNonce returns the 32 random bytes a request's code binds.
func (SystemSecrets) NewRequestNonce() ([32]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [32]byte{}, err
	}
	return nonce, nil
}

// Completion is where a replica's request stands for its session: still
// waiting, or completed with the gateway Device (Result).
type Completion struct {
	State  RequestState
	Result registration.Result
}

// JoinCompletionStore completes an approved request into its gateway Device
// in one transaction, bound to the session's machine key and node key, and
// returns the Device again for a request already completed. A request that
// waits returns RequestPending; one rejected or cancelled ErrNotWaiting;
// one past its deadline ErrExpired; one whose key was revoked
// ErrKeyNotUsable.
type JoinCompletionStore interface {
	CompleteReplicaRequest(ctx context.Context, scope network.Scope, requestID RequestID,
		identity node.RegistrationIdentity) (Completion, error)
}
