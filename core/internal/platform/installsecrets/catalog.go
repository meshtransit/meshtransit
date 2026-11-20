// Package installsecrets is the catalog of the secrets a Kubernetes install
// of Core generates (V1-11; docs/operations/configuration.md "Kubernetes
// bootstrap"): what
// each item is, its Secret and key, how it is generated and checked, and its
// public half when another party needs one. It does no I/O; the bootstrap
// command reads and creates the Secrets.
package installsecrets

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ErrPlan reports a plan the catalog cannot use.
var ErrPlan = errors.New("install secrets: invalid plan")

// Kind is how an item's value is generated and checked.
type Kind int

const (
	// KindLoginPassword is a PostgreSQL login's password, generated as 48
	// hex characters; one that exists is checked as the database bootstrap
	// checks it (32–256 printable ASCII, no space, quote or backslash).
	KindLoginPassword Kind = iota + 1
	// KindRedisPassword is a Redis user's password, generated like a login
	// password; one that exists is checked as the ACL step checks it (32–256
	// printable ASCII, no space).
	KindRedisPassword
	// KindKey is 32 random bytes in base64url without padding, the form
	// Core's key readers take strictly.
	KindKey
	// KindWrapKey is a 32-byte key generated as KindKey; one made by hand
	// may also be standard base64 or padded (`openssl rand -base64 32`),
	// which the wrap-key reader accepts.
	KindWrapKey
	// KindClientSecret is an OAuth client secret, generated as 64 hex
	// characters; one that exists may be any 32–4096 visible ASCII
	// characters, which both its readers (the identity broker and the
	// api's OIDC client) take.
	KindClientSecret
	// KindControlKey is the control's Noise key: "privkey:" and 64 hex.
	KindControlKey
	// KindBrowserKey is 32 random bytes in standard base64.
	KindBrowserKey
)

// Feature is an optional part of the install; items of a feature exist only
// when it is on.
type Feature string

// Features a plan may turn on.
const (
	FeatureIdentity       Feature = "identity"
	FeatureConnectionLogs Feature = "connectionLogs"
	FeatureKubernetesCA   Feature = "kubernetesCA"
	FeatureEntitlement    Feature = "entitlement"
)

// Public names the half another party needs, in the public-keys ConfigMap.
type Public string

// The public halves.
const (
	PublicNone           Public = ""
	PublicRelaySigning   Public = "relay-signing"
	PublicFlowLogSigning Public = "flowlog-signing"
	PublicInstallation   Public = "installation"
)

// Item is one secret of the catalog.
type Item struct {
	// ID names the item in the plan and, after the release name, its
	// default Secret: lower case, digits and dashes.
	ID string
	// Key is the key in the Secret: the file name the pod reads.
	Key  string
	Kind Kind
	// Retained marks a key whose loss breaks more than a restart: clients or
	// relays pin it, data is wrapped with it, the database holds digests
	// made with it (enrollment keys, identity subjects), or an entitlement
	// is signed on it. The
	// bootstrap never generates one for a database that already exists
	// unless the plan names it in allowNewRetainedKeys.
	Retained bool
	Public   Public
	// Login is the database login whose password this is, if any.
	Login   string
	Feature Feature
}

var itemID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)

// catalog is every item of the chart profiles, in creation order: the
// database logins first (the database step needs them).
var catalog = []Item{
	{ID: "login-mesh-migrator", Key: "password", Kind: KindLoginPassword, Login: "mesh_migrator"},
	{ID: "login-mesh-runtime", Key: "password", Kind: KindLoginPassword, Login: "mesh_runtime"},
	{ID: "login-mesh-control", Key: "password", Kind: KindLoginPassword, Login: "mesh_control"},
	{ID: "login-mesh-worker", Key: "password", Kind: KindLoginPassword, Login: "mesh_worker"},
	{ID: "login-identity-migrator", Key: "password", Kind: KindLoginPassword, Login: "identity_migrator",
		Feature: FeatureIdentity},
	{ID: "login-identity-runtime", Key: "password", Kind: KindLoginPassword, Login: "identity_runtime",
		Feature: FeatureIdentity},
	{ID: "redis-api", Key: "password", Kind: KindRedisPassword},
	{ID: "redis-control", Key: "password", Kind: KindRedisPassword},
	{ID: "redis-worker", Key: "password", Kind: KindRedisPassword},
	{ID: "control-noise", Key: "noise.key", Kind: KindControlKey, Retained: true},
	{ID: "enrollment-digest", Key: "enrollment-digest.key", Kind: KindKey, Retained: true},
	{ID: "browser-registration", Key: "browser-registration.key", Kind: KindBrowserKey},
	{ID: "relay-signing", Key: "relay-signing.key", Kind: KindKey, Retained: true, Public: PublicRelaySigning},
	{ID: "core-oidc-client-secret", Key: "core-oidc-client-secret", Kind: KindClientSecret},
	{ID: "account-session", Key: "account-session.key", Kind: KindKey},
	{ID: "capture", Key: "capture.key", Kind: KindKey},
	{ID: "continuation", Key: "continuation.key", Kind: KindKey},
	{ID: "idempotency", Key: "idempotency.key", Kind: KindKey},
	{ID: "initiation", Key: "initiation.key", Kind: KindKey},
	{ID: "management-csrf", Key: "management-csrf.key", Kind: KindKey},
	{ID: "provider-session", Key: "provider-session.key", Kind: KindKey},
	{ID: "rate-limit", Key: "rate-limit.key", Kind: KindKey},
	{ID: "subject-active", Key: "subject-active.key", Kind: KindKey, Retained: true},
	{ID: "transaction-digest", Key: "transaction-digest.key", Kind: KindKey},
	{ID: "verifier-encryption", Key: "verifier-encryption.key", Kind: KindKey},
	{ID: "flowlog-signing", Key: "signing.key", Kind: KindKey, Public: PublicFlowLogSigning,
		Feature: FeatureConnectionLogs},
	{ID: "kube-ca-wrap-key", Key: "wrap-key", Kind: KindWrapKey, Retained: true, Feature: FeatureKubernetesCA},
	{ID: "installation-seed", Key: "installation.seed", Kind: KindKey, Retained: true, Public: PublicInstallation,
		Feature: FeatureEntitlement},
}

// Profile is the kind of install a plan is for.
type Profile string

// The chart profiles. Both use the same catalog today; the profile is
// checked so a plan for another installer is refused.
const (
	ProfileCloud    Profile = "cloud"
	ProfileSelfHost Profile = "selfhost"
)

// Items is the catalog for profile with features on, in creation order.
func Items(profile Profile, features []Feature) ([]Item, error) {
	if profile != ProfileCloud && profile != ProfileSelfHost {
		return nil, fmt.Errorf("%w: profile %q", ErrPlan, profile)
	}
	for _, feature := range features {
		if !slices.Contains([]Feature{FeatureIdentity, FeatureConnectionLogs, FeatureKubernetesCA, FeatureEntitlement},
			feature) {
			return nil, fmt.Errorf("%w: feature %q", ErrPlan, feature)
		}
	}
	items := make([]Item, 0, len(catalog))
	for _, item := range catalog {
		if item.Feature == "" || slices.Contains(features, item.Feature) {
			items = append(items, item)
		}
	}
	return items, nil
}

// SecretName is the default Secret of item for the chart's fullname.
func SecretName(fullname string, item Item) string {
	return strings.TrimSuffix(fullname, "-") + "-" + item.ID
}

// ValidID reports whether id can name an item.
func ValidID(id string) bool { return itemID.MatchString(id) }
