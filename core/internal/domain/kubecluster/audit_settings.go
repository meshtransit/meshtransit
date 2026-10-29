package kubecluster

import (
	"context"
	"regexp"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// MaximumAuditSettingsEntries bounds each audit settings list.
const MaximumAuditSettingsEntries = 64

// secretResourcePattern is a resource as the chart lists it:
// resource[.group], lower case.
var secretResourcePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// AuditSettings are what an administrator says a cluster's gateway treats
// as privileged groups and secret-like resources, for meshctl kube
// audit-check (K1d §5, Q133). Version 0 means never set.
type AuditSettings struct {
	PrivilegedGroups []string
	SecretResources  []string
	Version          int64
	UpdatedAt        time.Time
}

// AuditSettingsReplacement replaces a cluster's audit settings when
// ExpectedVersion is the current one (0 before any).
type AuditSettingsReplacement struct {
	Session          accountsession.Session
	Scope            network.Scope
	ClusterID        ID
	ExpectedVersion  int64
	PrivilegedGroups []string
	SecretResources  []string
	CorrelationID    publicid.ID
}

// AuditSettingsResult is a replacement's outcome; Changed is false when the
// lists were already these.
type AuditSettingsResult struct {
	Settings AuditSettings
	Changed  bool
}

// NormalizeAuditSettingsList sorts and deduplicates a list; nil is empty,
// never SQL NULL.
func NormalizeAuditSettingsList(values []string) []string {
	normalized := append(make([]string, 0, len(values)), values...)
	slices.Sort(normalized)
	return slices.Compact(normalized)
}

// ReadAuditSettings returns a cluster's audit settings (network.read).
func (service *Service) ReadAuditSettings(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID) (AuditSettings, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return AuditSettings{}, err
	}
	if !clusterID.IsValid() {
		return AuditSettings{}, ErrInvalid
	}
	return service.store.ReadAuditSettings(ctx, session, scope, clusterID)
}

// ReplaceAuditSettings replaces a cluster's audit settings
// (kubernetes_cluster.manage and audit.export): sorted, distinct groups
// that are RFC 1123 labels, and resources in the chart's form.
func (service *Service) ReplaceAuditSettings(ctx context.Context,
	replacement AuditSettingsReplacement) (AuditSettingsResult, error) {
	if err := service.admit(ctx, replacement.Session, replacement.Scope); err != nil {
		return AuditSettingsResult{}, err
	}
	replacement.PrivilegedGroups = NormalizeAuditSettingsList(replacement.PrivilegedGroups)
	replacement.SecretResources = NormalizeAuditSettingsList(replacement.SecretResources)
	if !replacement.ClusterID.IsValid() || replacement.ExpectedVersion < 0 || !replacement.CorrelationID.IsValid() ||
		len(replacement.PrivilegedGroups) > MaximumAuditSettingsEntries ||
		len(replacement.SecretResources) > MaximumAuditSettingsEntries {
		return AuditSettingsResult{}, ErrInvalid
	}
	for _, group := range replacement.PrivilegedGroups {
		if !ValidKubernetesGroup(group) {
			return AuditSettingsResult{}, ErrInvalid
		}
	}
	for _, resource := range replacement.SecretResources {
		if len(resource) > 253 || !secretResourcePattern.MatchString(resource) {
			return AuditSettingsResult{}, ErrInvalid
		}
	}
	return service.store.ReplaceAuditSettings(ctx, replacement)
}
