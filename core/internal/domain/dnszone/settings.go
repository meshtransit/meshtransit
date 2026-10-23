package dnszone

import (
	"context"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// A Network's DNS settings (DNS design D5b): the Device Groups whose Devices
// get no DNS from MeshTransit, for machines that keep a company's DNS or
// another VPN's (schema 221).

// MaximumUnmanagedGroups bounds the unmanaged Device Groups of a Network.
const MaximumUnmanagedGroups = 16

// Settings are a Network's DNS settings at one version; version 0 is none
// set yet.
type Settings struct {
	Version         int64
	UnmanagedGroups []Group
}

// SettingsChange sets the unmanaged Device Groups when ExpectedVersion is
// still current.
type SettingsChange struct {
	Session         accountsession.Session
	Scope           network.Scope
	ExpectedVersion int64
	UnmanagedGroups []devicegroup.ID
	CorrelationID   publicid.ID
}

// SettingsResult is a settings change: the settings after it, and whether
// anything changed.
type SettingsResult struct {
	Settings      Settings
	Changed       bool
	AppliesWithin int
}

// SettingsStore reads and changes a Network's DNS settings.
type SettingsStore interface {
	ReadSettings(ctx context.Context, session accountsession.Session, scope network.Scope) (Settings, error)
	ChangeSettings(ctx context.Context, change SettingsChange) (SettingsResult, error)
}

// settingsStore returns the store's settings, when it keeps them.
func (service *Service) settingsStore() (SettingsStore, error) {
	store, ok := service.store.(SettingsStore)
	if !ok {
		return nil, ErrUnavailable
	}
	return store, nil
}

// ReadSettings reads the Network's DNS settings (network.read).
func (service *Service) ReadSettings(ctx context.Context, session accountsession.Session,
	scope network.Scope,
) (Settings, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return Settings{}, err
	}
	store, err := service.settingsStore()
	if err != nil {
		return Settings{}, err
	}
	return store.ReadSettings(ctx, session, scope)
}

// ChangeSettings sets the Network's unmanaged Device Groups (dns.manage) at
// the expected version: their Devices get no DNS configuration in their
// maps.
func (service *Service) ChangeSettings(ctx context.Context, session accountsession.Session, scope network.Scope,
	expectedVersion int64, unmanaged []devicegroup.ID, correlationID publicid.ID,
) (SettingsResult, error) {
	if err := service.admitWrite(ctx, session, scope, correlationID); err != nil {
		return SettingsResult{}, err
	}
	if expectedVersion < 0 || len(unmanaged) > MaximumUnmanagedGroups ||
		slices.ContainsFunc(unmanaged, func(group devicegroup.ID) bool { return !group.IsValid() }) {
		return SettingsResult{}, ErrInvalid
	}
	groups := slices.Clone(unmanaged)
	slices.SortFunc(groups, func(first, second devicegroup.ID) int {
		return strings.Compare(first.String(), second.String())
	})
	if len(slices.Compact(groups)) != len(unmanaged) {
		return SettingsResult{}, ErrInvalid
	}
	store, err := service.settingsStore()
	if err != nil {
		return SettingsResult{}, err
	}
	return store.ChangeSettings(ctx, SettingsChange{
		Session: session, Scope: scope, ExpectedVersion: expectedVersion, UnmanagedGroups: groups,
		CorrelationID: correlationID,
	})
}
