package entitlement

import (
	"encoding/base64"

	"meshtransit.net/core/internal/domain/deployment"
)

// trustedKey is one allowlisted issuer key. A self-renewal key names the one
// Deployment (installation public ID) and profile it may sign for; an
// offline issuance key names neither.
type trustedKey struct {
	public     string
	deployment string
	profile    deployment.Profile
}

// trustedKeys is the reviewed allowlist of issuer public keys. Adding a key is
// a code change; the matching private keys never enter this repository. A
// self-renewal key is added only for a Deployment whose ID is final (the POC
// gets one after its reset: runbooks/entitlement-renewal.md).
var trustedKeys = map[string]trustedKey{
	// POC issuance key, created 2026-10-05; private key held offline by the
	// product owner.
	"meshtransit-poc-2026-10": {public: "3HJd6S5O8Fb31Xa79DWKDaCNM52v7hqDX0CsApQuOLk="},
	// POC Cloud self-renewal key, created 2026-11-14; private key only in the
	// api role's Secret meshtransit-api-entitlement-renewal. Scoped to the POC
	// Deployment: replace it after the POC reset (runbooks/entitlement-renewal.md).
	"meshtransit-cloud-renew-2026": {
		public:     "bnFBonSKyNfh91eyPDajFbCqMinuXuG5lEWBwUSeook=",
		deployment: "01995d00-0000-7000-8000-000000000001",
		profile:    deployment.ProfileCloud,
	},
}

// TrustedVerifier returns a Verifier for the embedded allowlist.
func TrustedVerifier() (*Verifier, error) {
	return verifierFrom(trustedKeys)
}

// verifierFrom builds a Verifier from allowlist entries. The profile is
// always copied, so an entry with half a scope (a profile without a
// Deployment) is refused rather than trusted for every Deployment.
func verifierFrom(entries map[string]trustedKey) (*Verifier, error) {
	keys := make(map[string]TrustedKey, len(entries))
	for id, entry := range entries {
		key, err := base64.StdEncoding.Strict().DecodeString(entry.public)
		if err != nil {
			return nil, ErrInvalid
		}
		trusted := TrustedKey{Public: key, Profile: entry.profile}
		if entry.deployment != "" {
			if trusted.Deployment, err = deployment.ParseID(entry.deployment); err != nil {
				return nil, ErrInvalid
			}
		}
		keys[id] = trusted
	}
	return NewScopedVerifier(keys)
}
