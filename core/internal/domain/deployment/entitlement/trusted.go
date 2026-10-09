package entitlement

import (
	"crypto/ed25519"
	"encoding/base64"
)

// trustedKeys is the reviewed allowlist of issuer public keys. Adding a key is
// a code change; the matching private keys never enter this repository.
var trustedKeys = map[string]string{
	// POC issuance key, created 2026-10-05; private key held offline by the
	// product owner.
	"meshtransit-poc-2026-10": "3HJd6S5O8Fb31Xa79DWKDaCNM52v7hqDX0CsApQuOLk=",
}

// TrustedVerifier returns a Verifier for the embedded allowlist.
func TrustedVerifier() (*Verifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(trustedKeys))
	for id, encoded := range trustedKeys {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, ErrInvalid
		}
		keys[id] = key
	}
	return NewVerifier(keys)
}
