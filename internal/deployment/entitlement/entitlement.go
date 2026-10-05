// Package entitlement verifies the signed Deployment Entitlement (ADR-050 D1).
//
// An entitlement is issued outside Core by the MeshTransit deployment
// authority. Core only verifies: the Ed25519 signature under an allowlisted
// key ID, the Deployment binding, the installation key binding, the time
// window and the bounded limits. Profiles share one feature set; the
// entitlement carries only numeric limits and Cloud-only operations.
package entitlement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

// Format is the only accepted envelope and claims format.
const Format = "meshtransit-deployment-entitlement/v1"

const (
	// MaxEnvelopeBytes bounds the mounted entitlement file.
	MaxEnvelopeBytes = 16 << 10
	maxClockSkew     = 5 * time.Minute
	maxLifetime      = 3 * 366 * 24 * time.Hour
	maxGrace         = 90 * 24 * time.Hour
	maxWorkspaces    = 1_000_000
	maxOwnedPerAcct  = 1_000
)

var (
	// ErrInvalid reports a malformed envelope or claims. It never says which
	// check failed, so a probe learns nothing about the trusted keys.
	ErrInvalid = errors.New("entitlement: invalid")
	// ErrUntrusted reports an unknown key ID or a bad signature.
	ErrUntrusted = errors.New("entitlement: untrusted signature")
	// ErrForeign reports an entitlement for another Deployment or installation.
	ErrForeign = errors.New("entitlement: bound to another installation")
	// ErrNotYetValid reports an entitlement whose not_before is in the future.
	ErrNotYetValid = errors.New("entitlement: not yet valid")
)

var keyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Capability is a Cloud-only operation. Core features never depend on it.
type Capability string

const (
	// CapabilityCloudBilling enables the billing integration.
	CapabilityCloudBilling Capability = "cloud_billing"
	// CapabilityPlatformOperations enables the platform operations surface.
	CapabilityPlatformOperations Capability = "platform_operations"
)

func (capability Capability) isKnown() bool {
	return capability == CapabilityCloudBilling || capability == CapabilityPlatformOperations
}

// State is the entitlement's position in its validity window.
type State string

const (
	// StateActive is inside [not_before, expires_at).
	StateActive State = "active"
	// StateGrace is inside [expires_at, expires_at+grace).
	StateGrace State = "grace"
	// StateExpired is after grace: creation fails closed, tenants keep working.
	StateExpired State = "expired"
)

// Limits are the numeric bounds that distinguish profiles.
type Limits struct {
	MaxActiveWorkspaces          int64
	MaxOwnedWorkspacesPerAccount int64
}

// Entitlement is a verified claim set. Only Verifier.Verify constructs it.
type Entitlement struct {
	ID              publicid.ID
	DeploymentID    deployment.ID
	Profile         deployment.Profile
	Limits          Limits
	Capabilities    []Capability
	Generation      int64
	IssuedAt        time.Time
	NotBefore       time.Time
	ExpiresAt       time.Time
	Grace           time.Duration
	KeyID           string
	ContentSHA256   [sha256.Size]byte
	installationKey [sha256.Size]byte
}

// StateAt reports the validity state at an instant.
func (entitlement Entitlement) StateAt(now time.Time) State {
	switch {
	case now.Before(entitlement.ExpiresAt):
		return StateActive
	case now.Before(entitlement.ExpiresAt.Add(entitlement.Grace)):
		return StateGrace
	default:
		return StateExpired
	}
}

// Has reports whether a Cloud-only operation is entitled.
func (entitlement Entitlement) Has(capability Capability) bool {
	return slices.Contains(entitlement.Capabilities, capability)
}

// CapabilitiesSHA256 is a stable digest safe to log and expose.
func (entitlement Entitlement) CapabilitiesSHA256() string {
	digest := sha256.New()
	for _, capability := range entitlement.Capabilities {
		digest.Write([]byte(capability))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

type envelope struct {
	Format    string `json:"format"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type claims struct {
	Format                       string   `json:"format"`
	EntitlementID                string   `json:"entitlement_id"`
	DeploymentID                 string   `json:"deployment_id"`
	InstallationKeySHA256        string   `json:"installation_key_sha256"`
	Profile                      string   `json:"profile"`
	MaxActiveWorkspaces          int64    `json:"max_active_workspaces"`
	MaxOwnedWorkspacesPerAccount int64    `json:"max_owned_workspaces_per_account"`
	Capabilities                 []string `json:"capabilities"`
	Generation                   int64    `json:"generation"`
	IssuedAt                     string   `json:"issued_at"`
	NotBefore                    string   `json:"not_before"`
	ExpiresAt                    string   `json:"expires_at"`
	GraceSeconds                 int64    `json:"grace_seconds"`
}

// signingInput domain-separates the signature from any other Ed25519 use.
func signingInput(payload []byte) []byte {
	return append([]byte(Format+"\x00"), payload...)
}

// Verifier holds the allowlisted public verification keys.
type Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewVerifier copies a non-empty allowlist of key ID → Ed25519 public key.
func NewVerifier(keys map[string]ed25519.PublicKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, ErrInvalid
	}
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if !keyIDPattern.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		copied[id] = slices.Clone(key)
	}
	return &Verifier{keys: copied}, nil
}

// Verify checks one envelope for this Deployment and installation at now.
// An entitlement past its grace period still verifies with StateExpired, so
// existing tenants keep working while creation fails closed.
func (verifier *Verifier) Verify(raw []byte, deploymentID deployment.ID, installation *Installation,
	now time.Time) (Entitlement, error) {
	if verifier == nil || installation == nil || !deploymentID.IsValid() || now.IsZero() ||
		len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return Entitlement{}, ErrInvalid
	}
	var outer envelope
	if strictDecode(raw, &outer) != nil || outer.Format != Format || !keyIDPattern.MatchString(outer.KeyID) {
		return Entitlement{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(outer.Payload)
	if err != nil || len(payload) == 0 {
		return Entitlement{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(outer.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Entitlement{}, ErrInvalid
	}
	key, trusted := verifier.keys[outer.KeyID]
	if !trusted || !ed25519.Verify(key, signingInput(payload), signature) {
		return Entitlement{}, ErrUntrusted
	}
	result, err := parseClaims(payload)
	if err != nil {
		return Entitlement{}, err
	}
	result.KeyID = outer.KeyID
	result.ContentSHA256 = sha256.Sum256(payload)
	if result.DeploymentID != deploymentID || result.installationKey != installation.fingerprint() {
		return Entitlement{}, ErrForeign
	}
	if now.Add(maxClockSkew).Before(result.NotBefore) {
		return Entitlement{}, ErrNotYetValid
	}
	return result, nil
}

func parseClaims(payload []byte) (Entitlement, error) {
	var body claims
	if strictDecode(payload, &body) != nil || body.Format != Format {
		return Entitlement{}, ErrInvalid
	}
	id, idErr := publicid.Parse(body.EntitlementID)
	deploymentID, deploymentErr := deployment.ParseID(body.DeploymentID)
	installationKey, keyErr := hex.DecodeString(body.InstallationKeySHA256)
	issued, issuedErr := parseInstant(body.IssuedAt)
	notBefore, notBeforeErr := parseInstant(body.NotBefore)
	expires, expiresErr := parseInstant(body.ExpiresAt)
	profile := deployment.Profile(body.Profile)
	if errors.Join(idErr, deploymentErr, keyErr, issuedErr, notBeforeErr, expiresErr) != nil ||
		len(installationKey) != sha256.Size || body.InstallationKeySHA256 != hex.EncodeToString(installationKey) ||
		!profile.IsValid() || body.Generation <= 0 ||
		body.MaxActiveWorkspaces < 1 || body.MaxActiveWorkspaces > maxWorkspaces ||
		body.MaxOwnedWorkspacesPerAccount < 1 || body.MaxOwnedWorkspacesPerAccount > maxOwnedPerAcct ||
		body.MaxOwnedWorkspacesPerAccount > body.MaxActiveWorkspaces ||
		body.GraceSeconds < 0 || time.Duration(body.GraceSeconds)*time.Second > maxGrace ||
		issued.After(notBefore.Add(maxClockSkew)) || !expires.After(notBefore) ||
		expires.Sub(notBefore) > maxLifetime {
		return Entitlement{}, ErrInvalid
	}
	capabilities, err := parseCapabilities(body.Capabilities)
	if err != nil {
		return Entitlement{}, err
	}
	return Entitlement{
		ID: id, DeploymentID: deploymentID, Profile: profile,
		Limits: Limits{
			MaxActiveWorkspaces:          body.MaxActiveWorkspaces,
			MaxOwnedWorkspacesPerAccount: body.MaxOwnedWorkspacesPerAccount,
		},
		Capabilities: capabilities, Generation: body.Generation,
		IssuedAt: issued, NotBefore: notBefore, ExpiresAt: expires,
		Grace:           time.Duration(body.GraceSeconds) * time.Second,
		installationKey: [sha256.Size]byte(installationKey),
	}, nil
}

// parseCapabilities requires a strictly sorted list of known names.
func parseCapabilities(values []string) ([]Capability, error) {
	if values == nil {
		return nil, ErrInvalid
	}
	capabilities := make([]Capability, 0, len(values))
	for index, value := range values {
		capability := Capability(value)
		if !capability.isKnown() || (index > 0 && values[index-1] >= value) {
			return nil, ErrInvalid
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}

func parseInstant(value string) (time.Time, error) {
	instant, err := time.Parse(time.RFC3339, value)
	if err != nil || instant.Format(time.RFC3339) != value || instant.Location() != time.UTC {
		return time.Time{}, ErrInvalid
	}
	return instant, nil
}

func strictDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}
