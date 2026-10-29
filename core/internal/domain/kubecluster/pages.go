package kubecluster

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// MaximumPageSize bounds a page of join keys or replica requests (K1d
// Q131).
const MaximumPageSize = 100

// PageCursor names the last row of the page before: its time and public
// ID. The zero cursor starts at the newest row.
type PageCursor struct {
	At time.Time
	ID publicid.ID
}

// IsZero reports the first page.
func (cursor PageCursor) IsZero() bool { return cursor.At.IsZero() && cursor.ID == publicid.ID{} }

func (cursor PageCursor) isValid() bool {
	return cursor.IsZero() || !cursor.At.IsZero() && cursor.ID.IsValid()
}

// PageQuery asks for one page of a cluster's keys or requests, newest
// first.
type PageQuery struct {
	Session   accountsession.Session
	Scope     network.Scope
	ClusterID ID
	After     PageCursor
	Limit     int
}

// JoinKeyPage is a page of join keys; Next is zero on the last page.
type JoinKeyPage struct {
	Keys []JoinKey
	Next PageCursor
}

// RequestPage is a page of replica requests; Next is zero on the last page.
type RequestPage struct {
	Requests []ReplicaRequestView
	Next     PageCursor
}

func (service *Service) admitPage(ctx context.Context, query PageQuery) error {
	if err := service.admit(ctx, query.Session, query.Scope); err != nil {
		return err
	}
	if !query.ClusterID.IsValid() || query.Limit < 1 || query.Limit > MaximumPageSize || !query.After.isValid() {
		return ErrInvalid
	}
	return nil
}

// ListJoinKeys returns a page of a cluster's join keys
// (kubernetes_cluster.manage or .approve).
func (service *Service) ListJoinKeys(ctx context.Context, query PageQuery) (JoinKeyPage, error) {
	if err := service.admitPage(ctx, query); err != nil {
		return JoinKeyPage{}, err
	}
	return service.store.ListJoinKeys(ctx, query)
}

// ReadJoinKey returns one of a cluster's join keys.
func (service *Service) ReadJoinKey(ctx context.Context, session accountsession.Session, scope network.Scope,
	clusterID ID, keyID enrollment.CredentialID) (JoinKey, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return JoinKey{}, err
	}
	if !clusterID.IsValid() || !keyID.IsValid() {
		return JoinKey{}, ErrInvalid
	}
	return service.store.ReadJoinKey(ctx, session, scope, clusterID, keyID)
}

// ListReplicaRequests returns a page of a cluster's replica requests
// (kubernetes_cluster.manage or .approve).
func (service *Service) ListReplicaRequests(ctx context.Context, query PageQuery) (RequestPage, error) {
	if err := service.admitPage(ctx, query); err != nil {
		return RequestPage{}, err
	}
	return service.store.ListReplicaRequests(ctx, query)
}

// ReadReplicaRequest returns one of a cluster's replica requests.
func (service *Service) ReadReplicaRequest(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID, requestID RequestID) (ReplicaRequestView, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return ReplicaRequestView{}, err
	}
	if !clusterID.IsValid() || !requestID.IsValid() {
		return ReplicaRequestView{}, ErrInvalid
	}
	return service.store.ReadReplicaRequest(ctx, session, scope, clusterID, requestID)
}

// ReplicaPage is a page of a cluster's replicas; Next is zero on the last
// page.
type ReplicaPage struct {
	Replicas []Replica
	Next     PageCursor
}

// CAKind is a CA's tier.
type CAKind string

const (
	// CARoot is a cluster's root: clients trust it.
	CARoot CAKind = "root"
	// CAIntermediate signs the gateways' certificates.
	CAIntermediate CAKind = "intermediate"
)

// CertificateAuthority is one of a cluster's CAs as anyone in the Network
// may see it: never its private key (K1d d1b).
type CertificateAuthority struct {
	ID             publicid.ID
	Kind           CAKind
	IssuerID       publicid.ID
	State          string
	Reason         string
	StateReason    string
	Fingerprint    string
	Certificate    []byte
	ClusterDNSName string
	NotBefore      time.Time
	NotAfter       time.Time
	CreatedAt      time.Time
	ActivatedAt    time.Time
	RetiringAt     time.Time
	RetiredAt      time.Time
	// ChangedByOperator reports a change an operator made by command; who
	// and why stay in the audit trail.
	ChangedByOperator bool
	Version           int64
}

// CAPage is a page of a cluster's CAs; Next is zero on the last page.
type CAPage struct {
	CAs  []CertificateAuthority
	Next PageCursor
}

// ListReplicas returns a page of a cluster's replicas (network.read).
func (service *Service) ListReplicas(ctx context.Context, query PageQuery) (ReplicaPage, error) {
	if err := service.admitPage(ctx, query); err != nil {
		return ReplicaPage{}, err
	}
	return service.store.ListReplicas(ctx, query)
}

// ReadReplica returns one of a cluster's replicas.
func (service *Service) ReadReplica(ctx context.Context, session accountsession.Session, scope network.Scope,
	clusterID ID, deviceID node.ID) (Replica, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Replica{}, err
	}
	if !clusterID.IsValid() || !deviceID.IsValid() {
		return Replica{}, ErrInvalid
	}
	return service.store.ReadReplica(ctx, session, scope, clusterID, deviceID)
}

// MaximumCAPageSize bounds a page of CAs: a certificate takes up to 8 KiB.
const MaximumCAPageSize = 50

// ListCertificateAuthorities returns a page of a cluster's CAs
// (network.read).
func (service *Service) ListCertificateAuthorities(ctx context.Context, query PageQuery) (CAPage, error) {
	if err := service.admitPage(ctx, query); err != nil {
		return CAPage{}, err
	}
	if query.Limit > MaximumCAPageSize {
		return CAPage{}, ErrInvalid
	}
	return service.store.ListCertificateAuthorities(ctx, query)
}

// ReadCertificateAuthority returns one of a cluster's CAs.
func (service *Service) ReadCertificateAuthority(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID, caID publicid.ID) (CertificateAuthority, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return CertificateAuthority{}, err
	}
	if !clusterID.IsValid() || !caID.IsValid() {
		return CertificateAuthority{}, ErrInvalid
	}
	return service.store.ReadCertificateAuthority(ctx, session, scope, clusterID, caID)
}
