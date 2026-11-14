// Package renewal lets a Deployment's own Core renew its entitlement
// (auto-renewal-design.md §3): once the current generation has used two
// thirds of its life, the api role signs the same claims again as the next
// generation, for one year with 30 days of grace, under a self-renewal key
// the allowlist scopes to this Deployment. Changing a limit stays an offline
// issuance; the next renewal carries the new limits on.
package renewal

import (
	"crypto/ed25519"
	"errors"
	"log/slog"
	"math"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
	"meshtransit.net/core/internal/domain/deployment/entitlement/issuer"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	// Lifetime is a renewed generation's validity.
	Lifetime = 365 * 24 * time.Hour
	// notBeforeMargin starts a renewed generation a little before it is
	// signed, for the second truncated away and any clock between.
	notBeforeMargin = time.Minute
	// Grace follows Lifetime: creation still works, the next renewal is due.
	Grace = 30 * 24 * time.Hour
)

var (
	// ErrInvalidSigner rejects a renewal signer that cannot sign.
	ErrInvalidSigner = errors.New("entitlement renewal: invalid signer")
	// ErrNotRenewable reports a current generation this Deployment cannot
	// sign again (another profile, or a generation at its limit).
	ErrNotRenewable = errors.New("entitlement renewal: current generation cannot be renewed")
)

// Current is the recorded current generation's claims, with the database's
// clock read in the same transaction.
type Current struct {
	Generation   int64
	Profile      deployment.Profile
	Limits       entitlement.Limits
	Capabilities []entitlement.Capability
	NotBefore    time.Time
	ExpiresAt    time.Time
	SignerKeyID  string
	// DatabaseNow dates a renewal: Workspace creation and sign-up compare
	// not_before with the database's clock, so an api pod's clock running
	// ahead can never record a generation the database thinks is not valid
	// yet.
	DatabaseNow time.Time
}

// Due reports a generation that has used two thirds of its life, or more:
// a lapsed one (a database restored from an old backup) is due as well.
func Due(current Current, now time.Time) bool {
	span := current.ExpiresAt.Sub(current.NotBefore)
	return !now.Before(current.NotBefore.Add(span / 3 * 2))
}

// Signer signs the next generation with this Deployment's self-renewal key.
// The key never leaves it.
type Signer struct {
	keyID        string
	private      ed25519.PrivateKey
	installation *entitlement.Installation
	deploymentID deployment.ID
	verifier     *entitlement.Verifier
}

// NewSigner derives the key from seed (the caller clears it) and accepts it
// only if verifier allowlists it as this Deployment's cloud self-renewal key.
func NewSigner(keyID string, seed [ed25519.SeedSize]byte, installation *entitlement.Installation,
	deploymentID deployment.ID, verifier *entitlement.Verifier) (*Signer, error) {
	defer clear(seed[:])
	if installation == nil || verifier == nil || !deploymentID.IsValid() || seed == ([ed25519.SeedSize]byte{}) {
		return nil, ErrInvalidSigner
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	public, _ := private.Public().(ed25519.PublicKey)
	if err := verifier.CheckRenewalKey(keyID, public, deploymentID, deployment.ProfileCloud); err != nil {
		clear(private)
		return nil, errors.Join(ErrInvalidSigner, err)
	}
	return &Signer{keyID: keyID, private: private, installation: installation, deploymentID: deploymentID,
		verifier: verifier}, nil
}

// KeyID names the self-renewal key; it is safe to log.
func (signer *Signer) KeyID() string { return signer.keyID }

// String, GoString and LogValue never format the key.
func (signer *Signer) String() string {
	if signer == nil {
		return "renewal.Signer(nil)"
	}
	return "renewal.Signer(" + signer.keyID + ")"
}

// GoString redacts detailed formatting.
func (signer *Signer) GoString() string { return signer.String() }

// LogValue redacts structured logging.
func (signer *Signer) LogValue() slog.Value { return slog.StringValue(signer.String()) }

// forget clears the private key; the signer signs nothing after it.
func (signer *Signer) forget() {
	clear(signer.private)
	signer.private = nil
}

// Next signs current's claims as the next generation, valid from a minute
// before now (the database's clock), and returns it verified exactly as a
// mounted entitlement would be. A clock behind the current generation's
// start signs nothing.
func (signer *Signer) Next(current Current, now time.Time) (entitlement.Entitlement, error) {
	if signer == nil || now.IsZero() || len(signer.private) != ed25519.PrivateKeySize {
		return entitlement.Entitlement{}, ErrInvalidSigner
	}
	if current.Profile != deployment.ProfileCloud || current.Generation <= 0 ||
		current.Generation == math.MaxInt64 {
		return entitlement.Entitlement{}, ErrNotRenewable
	}
	id, err := publicid.New()
	if err != nil {
		return entitlement.Entitlement{}, err
	}
	start := now.UTC().Truncate(time.Second)
	if start.Before(current.NotBefore) {
		return entitlement.Entitlement{}, ErrNotRenewable
	}
	envelope, err := issuer.Sign(issuer.Claims{
		EntitlementID: id.String(), DeploymentID: signer.deploymentID.String(),
		InstallationPublicKey: signer.installation.PublicKey(), Profile: string(current.Profile),
		MaxActiveWorkspaces:          current.Limits.MaxActiveWorkspaces,
		MaxOwnedWorkspacesPerAccount: current.Limits.MaxOwnedWorkspacesPerAccount,
		Capabilities:                 slices.Clone(current.Capabilities), Generation: current.Generation + 1,
		IssuedAt: start, NotBefore: start.Add(-notBeforeMargin), ExpiresAt: start.Add(Lifetime), Grace: Grace,
	}, signer.keyID, signer.private)
	if err != nil {
		return entitlement.Entitlement{}, err
	}
	return signer.verifier.Verify(envelope, signer.deploymentID, signer.installation, start)
}
