package kubecluster

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
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
