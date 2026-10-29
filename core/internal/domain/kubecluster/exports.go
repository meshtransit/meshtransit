package kubecluster

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	// MaximumExportRange bounds the range one export covers (Q132).
	MaximumExportRange = 24 * time.Hour
	// ExportClockWindow widens the records past the range on each side:
	// Core's clock and the API server's differ (meshctl requires it).
	ExportClockWindow = 5 * time.Minute
	// MaximumExportRecords bounds the records of one export.
	MaximumExportRecords = 200000
	// ExportPageSize is the records one page of an export reads: up to
	// about 2.2 KiB each, under the 1 MiB a read decodes (review d1d-b M2).
	ExportPageSize = 400
)

// ExportQuery asks for a cluster's operations in [From, To) for meshctl
// kube audit-check (K1d d1d-b).
type ExportQuery struct {
	Session   accountsession.Session
	Scope     network.Scope
	ClusterID ID
	From      time.Time
	To        time.Time
}

// RecordsRange is the range the records cover: the query's, widened by
// ExportClockWindow on each side.
func (query ExportQuery) RecordsRange() (time.Time, time.Time) {
	return query.From.Add(-ExportClockWindow), query.To.Add(ExportClockWindow)
}

// ExportHeader opens an export: the gateway's namespace (empty without a
// signing trust), the audit settings, and how many records the range holds
// (counted up to MaximumExportRecords + 1).
type ExportHeader struct {
	ClusterID        ID
	GatewayNamespace string
	Settings         AuditSettings
	Count            int
}

// ExportRecord is one operation as meshctl kube audit-check reads it;
// Status is 0 without an outcome within a day.
type ExportRecord struct {
	AuditID      publicid.ID
	ReceivedAt   time.Time
	Class        string
	Groups       []string
	Verb         string
	APIGroup     string
	Resource     string
	Subresource  string
	Namespace    string
	Name         string
	Impersonated string
	Status       int
}

func (service *Service) admitExport(ctx context.Context, query ExportQuery) error {
	if err := service.admit(ctx, query.Session, query.Scope); err != nil {
		return err
	}
	if !query.ClusterID.IsValid() || !query.To.After(query.From) || query.To.Sub(query.From) > MaximumExportRange {
		return ErrInvalid
	}
	return nil
}

// BeginExport reads an export's header and count (audit.export).
func (service *Service) BeginExport(ctx context.Context, query ExportQuery) (ExportHeader, error) {
	if err := service.admitExport(ctx, query); err != nil {
		return ExportHeader{}, err
	}
	return service.store.BeginExport(ctx, query)
}

// ExportPage reads the ExportPageSize records after after, oldest first.
func (service *Service) ExportPage(ctx context.Context, query ExportQuery, after PageCursor) ([]ExportRecord, error) {
	if err := service.admitExport(ctx, query); err != nil {
		return nil, err
	}
	if !after.isValid() {
		return nil, ErrInvalid
	}
	return service.store.ExportPage(ctx, query, after)
}
