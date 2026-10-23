package sharing

import (
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// ContractServiceNames are the service names of a running share as one of
// its Networks sees them (DNS design D3 §19): the provider's current
// suggestions, which it may change while the contract runs, and for the
// consumer the DNS names of its Network that point at the share. The
// provider never sees those.
type ContractServiceNames struct {
	ContractID ContractID
	// Provider reports that the reading Network is the provider.
	Provider bool
	// State is the contract's state as stored: activating, active, revoked,
	// expired or invalidated.
	State     string
	ExpiresAt time.Time
	// Version counts the provider's changes: 0 while the suggestions are
	// still the offer's.
	Version int64
	Names   []ServiceName
	// ShareID is the share the consumer imports; zero for the provider.
	ShareID  ImportedResourceID
	DNSNames []ContractDNSName
}

// Running reports whether the contract still runs at now: active or
// activating, before its end.
func (names ContractServiceNames) Running(now time.Time) bool {
	return (names.State == "active" || names.State == "activating") && now.Before(names.ExpiresAt)
}

// Suggests reports whether name is one of the current suggestions.
func (names ContractServiceNames) Suggests(name ServiceName) bool {
	for _, suggested := range names.Names {
		if suggested == name {
			return true
		}
	}
	return false
}

// ContractDNSName is a DNS name of the consumer Network that points at the
// share.
type ContractDNSName struct {
	ID     publicid.ID
	ZoneID publicid.ID
	FQDN   string
}

var (
	// ErrServiceNamesChanged reports suggestions another change replaced
	// since the version the caller read.
	ErrServiceNamesChanged = errors.New("sharing: service names changed")
	// ErrContractEnded reports a contract that no longer runs.
	ErrContractEnded = errors.New("sharing: contract has ended")
	// ErrServiceNameNotSuggested reports a name the provider does not
	// suggest (any more).
	ErrServiceNameNotSuggested = errors.New("sharing: service name not suggested")
)
