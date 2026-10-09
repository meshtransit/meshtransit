// Package issuer signs Deployment Entitlements. It belongs to the issuance
// boundary (operator tool and tests) and must never be linked into meshcore.
package issuer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment/entitlement"
)

// ErrInvalid reports claims the verifier would reject.
var ErrInvalid = errors.New("issuer: invalid claims")

// Claims is the issuer-side input. Times are truncated to whole UTC seconds.
type Claims struct {
	EntitlementID                string
	DeploymentID                 string
	InstallationPublicKey        ed25519.PublicKey
	Profile                      string
	MaxActiveWorkspaces          int64
	MaxOwnedWorkspacesPerAccount int64
	Capabilities                 []entitlement.Capability
	Generation                   int64
	IssuedAt                     time.Time
	NotBefore                    time.Time
	ExpiresAt                    time.Time
	Grace                        time.Duration
}

type payload struct {
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

type envelope struct {
	Format    string `json:"format"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func instant(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// Sign produces one envelope under keyID. The caller owns the signing key.
func Sign(claims Claims, keyID string, signingKey ed25519.PrivateKey) ([]byte, error) {
	if len(signingKey) != ed25519.PrivateKeySize || len(claims.InstallationPublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalid
	}
	capabilities := make([]string, 0, len(claims.Capabilities))
	for _, capability := range claims.Capabilities {
		capabilities = append(capabilities, string(capability))
	}
	slices.Sort(capabilities)
	fingerprint := sha256.Sum256(claims.InstallationPublicKey)
	body, err := json.Marshal(payload{
		Format: entitlement.Format, EntitlementID: claims.EntitlementID, DeploymentID: claims.DeploymentID,
		InstallationKeySHA256: hex.EncodeToString(fingerprint[:]), Profile: claims.Profile,
		MaxActiveWorkspaces:          claims.MaxActiveWorkspaces,
		MaxOwnedWorkspacesPerAccount: claims.MaxOwnedWorkspacesPerAccount,
		Capabilities:                 capabilities, Generation: claims.Generation,
		IssuedAt: instant(claims.IssuedAt), NotBefore: instant(claims.NotBefore),
		ExpiresAt: instant(claims.ExpiresAt), GraceSeconds: int64(claims.Grace / time.Second),
	})
	if err != nil {
		return nil, ErrInvalid
	}
	message := append([]byte(entitlement.Format+"\x00"), body...)
	return json.Marshal(envelope{
		Format: entitlement.Format, KeyID: keyID,
		Payload:   base64.RawURLEncoding.EncodeToString(body),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signingKey, message)),
	})
}
