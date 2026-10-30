package kubecluster

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// MaximumAccessContact bounds a cluster's access contact, in bytes: what
// its gateways name when an access profile refuses a request (K2 §9.2).
const MaximumAccessContact = 256

// AccessSettings are a cluster's access settings (K2 §29.1): who to ask for
// more access, empty for none. Version 0 means never set.
type AccessSettings struct {
	AccessContact string
	Version       int64
	UpdatedAt     time.Time
}

// AccessSettingsReplacement replaces a cluster's access settings when
// ExpectedVersion is the current one (0 before any).
type AccessSettingsReplacement struct {
	Session         accountsession.Session
	Scope           network.Scope
	ClusterID       ID
	ExpectedVersion int64
	AccessContact   string
	CorrelationID   publicid.ID
}

// AccessSettingsResult is a replacement's outcome; Changed is false when
// the contact was already this.
type AccessSettingsResult struct {
	Settings AccessSettings
	Changed  bool
}

// ValidAccessContact reports a contact a gateway may show in a refusal:
// UTF-8 of at most MaximumAccessContact bytes without control or format
// characters, nor spaces around it; empty is none.
func ValidAccessContact(contact string) bool {
	if len(contact) > MaximumAccessContact || !utf8.ValidString(contact) || contact != strings.TrimSpace(contact) {
		return false
	}
	for _, character := range contact {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

// ReadAccessSettings returns a cluster's access settings (network.read).
func (service *Service) ReadAccessSettings(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID) (AccessSettings, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return AccessSettings{}, err
	}
	if !clusterID.IsValid() {
		return AccessSettings{}, ErrInvalid
	}
	return service.store.ReadAccessSettings(ctx, session, scope, clusterID)
}

// ReplaceAccessSettings replaces a cluster's access contact
// (kubernetes_cluster.manage); its gateways get it with their next map.
func (service *Service) ReplaceAccessSettings(ctx context.Context,
	replacement AccessSettingsReplacement) (AccessSettingsResult, error) {
	if err := service.admit(ctx, replacement.Session, replacement.Scope); err != nil {
		return AccessSettingsResult{}, err
	}
	if !replacement.ClusterID.IsValid() || replacement.ExpectedVersion < 0 || !replacement.CorrelationID.IsValid() ||
		!ValidAccessContact(replacement.AccessContact) {
		return AccessSettingsResult{}, ErrInvalid
	}
	return service.store.ReplaceAccessSettings(ctx, replacement)
}
