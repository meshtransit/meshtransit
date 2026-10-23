package daemon

import (
	"context"
	"errors"

	"meshtransit.net/client/internal/dnsconfig"
)

// ErrDNSInactive reports that this node's resolver does not run, so there
// is nothing to ask.
var ErrDNSInactive = errors.New("daemon: the DNS resolver is not running")

// dnsQuerier is a DNS controller whose resolver answers diagnostic
// questions (meshctl dns query, DNS design D5f).
type dnsQuerier interface {
	Query(context.Context, string, string) (dnsconfig.QueryReport, error)
}

// QueryDNS asks the node's resolver name of type typeName, as an
// application would, and reports where it went and what came back.
func (s *Service) QueryDNS(ctx context.Context, name, typeName string) (dnsconfig.QueryReport, error) {
	if s == nil || s.dns == nil {
		return dnsconfig.QueryReport{}, ErrDNSInactive
	}
	querier, ok := s.dns.(dnsQuerier)
	if !ok {
		return dnsconfig.QueryReport{}, ErrDNSInactive
	}
	report, err := querier.Query(ctx, name, typeName)
	if errors.Is(err, dnsconfig.ErrQueryUnavailable) {
		return report, ErrDNSInactive
	}
	return report, err
}
