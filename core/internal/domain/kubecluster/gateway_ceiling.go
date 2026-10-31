package kubecluster

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubeprofile"
)

// A gateway's group ceilings (K2h h4, mtcp-v1 §6.12): what each group's own
// RBAC lets it do, as the gateway measured it. Shown to people as a lower
// bound, never a security decision.
const (
	maximumCeilingGroups     = 64
	maximumCeilingNamespaces = 16
	maximumCeilingRules      = 576
	maximumCeilingList       = 64
	maximumCeilingString     = 253
	// MaximumCeilingBytes bounds a ceiling as Core encodes it.
	MaximumCeilingBytes = 1 << 20
	// MaximumCeilingBodies bounds the distinct ceilings one read returns.
	MaximumCeilingBodies = 4
	// CeilingStaleAfter is how old a ceiling reads as stale: a gateway sends
	// its ceiling at least every 6 hours.
	CeilingStaleAfter = 24 * time.Hour
)

// CeilingScope is what a group may do in one namespace, or everywhere
// (Namespace empty): Measured false says nothing else.
type CeilingScope struct {
	Namespace    string             `json:"namespace"`
	Measured     bool               `json:"measured"`
	Incomplete   bool               `json:"incomplete"`
	RulesDropped int64              `json:"rules_dropped"`
	Rules        []kubeprofile.Rule `json:"rules"`
}

// CeilingGroup is one group's ceiling.
type CeilingGroup struct {
	Group               string         `json:"group"`
	ClusterRole         string         `json:"cluster_role"`
	Everywhere          CeilingScope   `json:"everywhere"`
	Namespaces          []CeilingScope `json:"namespaces"`
	NamespacesTruncated bool           `json:"namespaces_truncated"`
}

// CeilingBody is a gateway's ceiling as Core keeps it.
type CeilingBody struct {
	Groups    []CeilingGroup `json:"groups"`
	Truncated bool           `json:"truncated"`
}

// EncodedCeiling is a ceiling a gateway session sent, as Core encoded and
// hashed it once on receipt: only CeilingBody.Encoded makes one, so its
// bytes are a valid body and its hash theirs.
type EncodedCeiling struct {
	encoded    []byte
	hash       [32]byte
	checkedAt  time.Time
	receivedAt time.Time
}

// Encoded is the body encoded with when it was measured (zero: not shown)
// and received; it fails on a body ValidCeilingBody refuses or over
// MaximumCeilingBytes.
func (body CeilingBody) Encoded(checkedAt, receivedAt time.Time) (EncodedCeiling, error) {
	encoded, hash, err := body.Encode()
	if err != nil || receivedAt.IsZero() {
		return EncodedCeiling{}, ErrInvalid
	}
	return EncodedCeiling{encoded: encoded, hash: hash, checkedAt: checkedAt, receivedAt: receivedAt}, nil
}

// Bytes is the encoded body; callers must not change it.
func (ceiling EncodedCeiling) Bytes() []byte { return ceiling.encoded }

// Hash is the SHA-256 of Bytes.
func (ceiling EncodedCeiling) Hash() [32]byte { return ceiling.hash }

// CheckedAt is when the gateway's measurement ended; zero: not shown.
func (ceiling EncodedCeiling) CheckedAt() time.Time { return ceiling.checkedAt }

// ReceivedAt is when Core took it: an older one never replaces a newer.
func (ceiling EncodedCeiling) ReceivedAt() time.Time { return ceiling.receivedAt }

// IsZero reports a ceiling Encoded did not make.
func (ceiling EncodedCeiling) IsZero() bool { return len(ceiling.encoded) == 0 }

// Encode is the body as Core stores and hashes it, and its SHA-256: the
// same body encodes alike. It fails on a body ValidCeilingBody refuses.
func (body CeilingBody) Encode() ([]byte, [32]byte, error) {
	if !ValidCeilingBody(body) {
		return nil, [32]byte{}, ErrInvalid
	}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > MaximumCeilingBytes {
		return nil, [32]byte{}, ErrInvalid
	}
	return encoded, sha256.Sum256(encoded), nil
}

// ValidCeilingBody reports a body within §6.12: at most 64 distinct groups,
// each with an unnamed everywhere scope and at most 16 distinct named
// namespaces; an unmeasured scope empty; a measured one at most 576 rules
// of printable ASCII within bounds. Lists are never nil, so the encoding is
// one.
func ValidCeilingBody(body CeilingBody) bool {
	if body.Groups == nil || len(body.Groups) > maximumCeilingGroups {
		return false
	}
	groups := make(map[string]struct{}, len(body.Groups))
	for _, group := range body.Groups {
		if _, twice := groups[group.Group]; twice || !ValidKubernetesGroup(group.Group) ||
			group.ClusterRole != "" && !validClusterRoleName(group.ClusterRole) ||
			group.Everywhere.Namespace != "" || !validCeilingScope(group.Everywhere) ||
			group.Namespaces == nil || len(group.Namespaces) > maximumCeilingNamespaces {
			return false
		}
		groups[group.Group] = struct{}{}
		namespaces := make(map[string]struct{}, len(group.Namespaces))
		for _, scope := range group.Namespaces {
			// A namespace is a DNS label, as a group is named.
			if _, twice := namespaces[scope.Namespace]; twice || !ValidKubernetesGroup(scope.Namespace) ||
				!validCeilingScope(scope) {
				return false
			}
			namespaces[scope.Namespace] = struct{}{}
		}
	}
	return true
}

func validCeilingScope(scope CeilingScope) bool {
	if scope.Rules == nil || scope.RulesDropped < 0 {
		return false
	}
	if !scope.Measured {
		return len(scope.Rules) == 0 && !scope.Incomplete && scope.RulesDropped == 0
	}
	if len(scope.Rules) > maximumCeilingRules {
		return false
	}
	for _, rule := range scope.Rules {
		if !validCeilingRule(rule) {
			return false
		}
	}
	return true
}

// validCeilingRule is a resource rule (verbs, API groups, resources,
// perhaps names) or a path rule (verbs and paths).
func validCeilingRule(rule kubeprofile.Rule) bool {
	for _, list := range [][]string{rule.Verbs, rule.APIGroups, rule.Resources, rule.ResourceNames,
		rule.NonResourceURLs} {
		if len(list) > maximumCeilingList {
			return false
		}
		for _, value := range list {
			if !printableCeiling(value) {
				return false
			}
		}
	}
	if len(rule.Verbs) == 0 {
		return false
	}
	if len(rule.NonResourceURLs) > 0 {
		return len(rule.APIGroups) == 0 && len(rule.Resources) == 0 && len(rule.ResourceNames) == 0
	}
	return len(rule.Resources) > 0 && len(rule.APIGroups) > 0
}

func printableCeiling(value string) bool {
	if len(value) > maximumCeilingString {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validClusterRoleName(name string) bool {
	return name != "." && name != ".." && !strings.ContainsAny(name, "/%") && printableCeiling(name)
}

// ReplicaCeiling is a replica's latest ceiling as people read it: its hash
// names the body, none when the replica has not reported one.
type ReplicaCeiling struct {
	DeviceID    node.ID
	ReceivedAt  time.Time
	CheckedAt   time.Time
	ContentHash string // hex; empty: no ceiling yet
}

// CeilingDocument is one distinct ceiling of a cluster.
type CeilingDocument struct {
	ContentHash string
	Body        CeilingBody
}

// ClusterCeilings are a cluster's active replicas and the bodies of at most
// MaximumCeilingBodies distinct ceilings among them, the most recently
// received first; a reader asks for another by its hash.
type ClusterCeilings struct {
	Replicas []ReplicaCeiling
	Bodies   []CeilingDocument
}

// ListGroupCeilings returns a cluster's active replicas with their latest
// ceilings (network.read, as the replicas).
func (service *Service) ListGroupCeilings(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID) (ClusterCeilings, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return ClusterCeilings{}, err
	}
	if !clusterID.IsValid() {
		return ClusterCeilings{}, ErrInvalid
	}
	return service.store.ListGroupCeilings(ctx, session, scope, clusterID)
}

// ReadGroupCeiling returns one of a cluster's ceilings by its hash, held by
// an active replica (network.read); ErrNotFound when none holds it.
func (service *Service) ReadGroupCeiling(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID ID, contentHash [32]byte) (CeilingDocument, error) {
	if err := service.admit(ctx, session, scope); err != nil {
		return CeilingDocument{}, err
	}
	if !clusterID.IsValid() || contentHash == ([32]byte{}) {
		return CeilingDocument{}, ErrInvalid
	}
	return service.store.ReadGroupCeiling(ctx, session, scope, clusterID, contentHash)
}
