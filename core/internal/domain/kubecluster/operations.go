package kubecluster

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	// OperationScanBudget bounds the rows one page of operations reads,
	// whatever the filters keep (K1d Q140).
	OperationScanBudget = 50000
	// MaximumOperationRange bounds a range of operations or denials.
	MaximumOperationRange = 31 * 24 * time.Hour
	// MaximumFilteredOperationRange bounds a range read with a filter.
	MaximumFilteredOperationRange = 24 * time.Hour
	// MaximumOwnerRef bounds a person or tags filter.
	MaximumOwnerRef = 1024
)

var operationClasses = map[string]bool{"write": true, "exec": true, "proxy": true, "secret_read": true,
	"privileged": true, "unparsed": true}

// Operation is one type A operation a gateway recorded, as an audit reader
// sees it (K1b0, K1d d1c). Status is 0 without an outcome within a day.
type Operation struct {
	AuditID         publicid.ID
	ReceivedAt      time.Time
	Class           string
	Groups          []string
	Verb            string
	APIGroup        string
	Resource        string
	Subresource     string
	Namespace       string
	Name            string
	Impersonated    string
	OwnerKind       string
	OwnerRef        string
	NetworkRevision int64
	ClockSkew       bool
	GatewayDeviceID node.ID
	PeerDeviceID    node.ID
	// HasOutcome reports an outcome within a day: Status and DurationMS.
	HasOutcome bool
	Status     int
	DurationMS int
}

// OperationQuery asks for a page of a cluster's operations in [From, To),
// newest first, kept by the optional filters.
type OperationQuery struct {
	Session      accountsession.Session
	Scope        network.Scope
	ClusterID    ID
	From         time.Time
	To           time.Time
	After        PageCursor
	OwnerRef     string
	PeerDeviceID node.ID
	Class        string
	Limit        int
	// ScanBudget bounds the rows the page reads; zero is
	// OperationScanBudget, and no query may ask for more.
	ScanBudget int
}

// Filtered reports a query with a filter: its range is shorter.
func (query OperationQuery) Filtered() bool {
	return query.OwnerRef != "" || query.PeerDeviceID.IsValid() || query.Class != ""
}

// OperationPage is a page of operations. Next continues the read, zero on
// the last page; Truncated says the scan budget ran out before the page
// filled, so Next is the last row scanned, not the last row kept.
type OperationPage struct {
	Operations []Operation
	Next       PageCursor
	Truncated  bool
}

// DenialSums are a cluster's denials over a range by reason: over the
// newest 50000 denial rows at most, so Truncated says older ones were left
// out and CountedFrom is the oldest summed (Q153).
type DenialSums struct {
	Counts      []DenialCount
	Truncated   bool
	CountedFrom time.Time
}

// DenialCount sums a cluster's denials of one reason over a range.
type DenialCount struct {
	Reason  string
	Count   int64
	FirstAt time.Time
	LastAt  time.Time
}

// ListOperations returns a page of a cluster's operations (audit.read).
func (service *Service) ListOperations(ctx context.Context, query OperationQuery) (OperationPage, error) {
	if err := service.admit(ctx, query.Session, query.Scope); err != nil {
		return OperationPage{}, err
	}
	maximum := MaximumOperationRange
	if query.Filtered() {
		maximum = MaximumFilteredOperationRange
	}
	if !query.ClusterID.IsValid() || !query.To.After(query.From) || query.To.Sub(query.From) > maximum ||
		query.Limit < 1 || query.Limit > MaximumPageSize || !query.After.isValid() ||
		len(query.OwnerRef) > MaximumOwnerRef || query.Class != "" && !operationClasses[query.Class] ||
		query.ScanBudget < 0 || query.ScanBudget > OperationScanBudget {
		return OperationPage{}, ErrInvalid
	}
	if query.ScanBudget == 0 {
		query.ScanBudget = OperationScanBudget
	}
	return service.store.ListOperations(ctx, query)
}

// ReadOperation returns one of a cluster's operations by its audit ID.
func (service *Service) ReadOperation(ctx context.Context, session accountsession.Session, scope network.Scope,
	clusterID ID, auditID publicid.ID) (Operation, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Operation{}, err
	}
	if !clusterID.IsValid() || !auditID.IsValid() {
		return Operation{}, ErrInvalid
	}
	return service.store.ReadOperation(ctx, session, scope, clusterID, auditID)
}

// CountDenials sums a cluster's denials in [from, to) by reason
// (audit.read).
func (service *Service) CountDenials(ctx context.Context, session accountsession.Session, scope network.Scope,
	clusterID ID, from, to time.Time) (DenialSums, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return DenialSums{}, err
	}
	if !clusterID.IsValid() || !to.After(from) || to.Sub(from) > MaximumOperationRange {
		return DenialSums{}, ErrInvalid
	}
	return service.store.CountDenials(ctx, session, scope, clusterID, from, to)
}
