package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrInstallationKey reports an unusable installation private key.
var ErrInstallationKey = errors.New("entitlement: invalid installation key")

// Installation is this Core installation's Ed25519 identity. An entitlement
// names its public-key fingerprint, so a copied entitlement without the
// matching private key is rejected as foreign.
type Installation struct {
	public ed25519.PublicKey
}

// NewInstallation derives the identity from a 32-byte Ed25519 seed, read by
// the hardened key-file reader, and proves possession by signing a fresh
// challenge. The private key is not retained.
func NewInstallation(seed [ed25519.SeedSize]byte) (*Installation, error) {
	if seed == ([ed25519.SeedSize]byte{}) {
		return nil, ErrInstallationKey
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	defer clear(private)
	public, ok := private.Public().(ed25519.PublicKey)
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil || !ok {
		return nil, ErrInstallationKey
	}
	message := append([]byte(Format+"\x00installation-proof\x00"), challenge...)
	if !ed25519.Verify(public, message, ed25519.Sign(private, message)) {
		return nil, ErrInstallationKey
	}
	return &Installation{public: public}, nil
}

func (installation *Installation) fingerprint() [sha256.Size]byte {
	return sha256.Sum256(installation.public)
}

// Fingerprint is the lowercase hex SHA-256 of the public key, which the
// issuer puts in installation_key_sha256. It is safe to log.
func (installation *Installation) Fingerprint() string {
	digest := installation.fingerprint()
	return hex.EncodeToString(digest[:])
}
