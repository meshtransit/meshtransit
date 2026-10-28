// Package kubecert keeps a Kubernetes gateway's replica certificate
// (K1a4a a4, the meshgw certificate design v2): it asks Core for one with
// the pod's token after the pod starts, renews it with the current key a
// third into its life, early when the map names other CAs, and checks every
// certificate Core returns before it takes it. Keys live in memory only.
package kubecert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"log/slog"
	"math/big"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

const (
	// renewFloor is the least wait before a renewal, and minimumReissue
	// the least time between two certificates unless the root changed
	// (design §10 M1).
	renewFloor     = time.Minute
	minimumReissue = 15 * time.Minute
	// shortLife is the life left under which the renewal moves to a
	// quarter of what is left (§10 M1).
	shortLife = 12 * time.Hour
	// backoffFloor and backoffCeiling bound retries (§3.2 step 3); the
	// ceiling also caps at a twentieth of the life left.
	backoffFloor   = 2 * time.Second
	backoffCeiling = 5 * time.Minute
	backoffMinimum = 30 * time.Second
	// failureCeiling bounds the wait after a certificate that failed its
	// checks or a request of the wrong form (§10 H1).
	failureCeiling = time.Hour
	// tokenWaitLimit is the longest wait for a new pod token (§10 H2), and
	// mapWait for a map that names a signing CA.
	tokenWaitLimit = 10 * time.Minute
	mapWait        = 5 * time.Minute
	// minimumTokenWait is the least wait for a new token (spec §6.9).
	minimumTokenWait = time.Minute
	// stopWait is the wait after a refusal that ends asking for now
	// (revoked, cluster, not_gateway, not_proven).
	stopWait = 10 * time.Minute
	// rootJitter and signingJitter cap how far an early renewal spreads
	// (§10 M5); both also cap at a quarter of the life left.
	rootJitter    = time.Hour
	signingJitter = time.Hour
	// skew is the clock tolerance when a certificate's validity is checked.
	skew = 5 * time.Minute
)

// Certificate is the gateway's current replica certificate and its key.
type Certificate struct {
	Key   *ecdsa.PrivateKey
	Leaf  *x509.Certificate
	DER   []byte
	Chain [][]byte
	// Serial is the leaf's serial in the 16 bytes a renewal names.
	Serial          [16]byte
	Root, Issuer    [32]byte
	NotAfter        time.Time
	RenewAt         time.Time // Core's, by its clock
	NetworkRevision uint64
	// IssuedAt is when it was taken, by the Core clock.
	IssuedAt time.Time
}

// String redacts the certificate, which holds its private key.
func (Certificate) String() string { return "kubecert.Certificate([REDACTED])" }

// GoString redacts detailed formatting.
func (Certificate) GoString() string { return "kubecert.Certificate([REDACTED])" }

// LogValue redacts structured formatting.
func (Certificate) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// renewalTime is when to renew cert, fixed when it was taken (never
// sliding with the clock): Core's renew_at, a third into the life; a
// certificate taken with under 12 hours left, a quarter of what it had; at
// least a minute after it was taken, and 15 minutes unless rootChanged
// (§10 M1). Retries after that follow their own backoff.
func renewalTime(cert Certificate, rootChanged bool) time.Time {
	life := cert.NotAfter.Sub(cert.IssuedAt)
	at := cert.RenewAt
	// Core's time never past half the life (spec §6.9: 12 hours of a 24-hour
	// certificate), so a renew_at at or past the end cannot make the whole
	// fleet run to expiry together (a4b1 review M4).
	if latest := cert.NotAfter.Add(-life / 2); at.After(latest) {
		at = latest
	}
	if life < shortLife {
		at = cert.IssuedAt.Add(max(renewFloor, life/4))
	}
	if earliest := cert.IssuedAt.Add(renewFloor); at.Before(earliest) {
		at = earliest
	}
	if earliest := cert.IssuedAt.Add(minimumReissue); !rootChanged && at.Before(earliest) {
		at = earliest
	}
	return at
}

// backoff is the n-th retry wait (n ≥ 1), jittered, capped by the life left
// (§3.2 step 3).
func backoff(n int, remaining time.Duration) time.Duration {
	ceiling := max(backoffMinimum, min(backoffCeiling, remaining/20))
	wait := backoffFloor
	for range n - 1 {
		if wait >= ceiling {
			break
		}
		wait *= 2
	}
	return jitter(min(wait, ceiling))
}

// failureBackoff is the n-th wait after a failure only a new key may cure:
// from a minute up to an hour (§10 H1).
func failureBackoff(n int) time.Duration {
	wait := time.Minute
	for range n - 1 {
		if wait >= failureCeiling {
			break
		}
		wait *= 2
	}
	return jitter(min(wait, failureCeiling))
}

// jitter spreads wait over half to the whole of it.
func jitter(wait time.Duration) time.Duration {
	if wait <= 1 {
		return wait
	}
	return wait/2 + random(wait/2)
}

// random is uniform in [0, spread).
func random(spread time.Duration) time.Duration {
	if spread <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(spread)))
	if err != nil {
		return spread / 2
	}
	return time.Duration(value.Int64())
}

// earlyRenewal reports whether the map names CAs other than cert's and how
// far to spread the renewal (§3.3, R-M6): only a map at or past the
// certificate's revision counts; absent, no CA yet, or a root without a
// signing intermediate never does. A new root renews within its jitter, a
// new intermediate within its own; both cap at a quarter of the life left.
func earlyRenewal(cert Certificate, ca *networkmap.KubernetesCA, now time.Time) (time.Duration, bool, bool) {
	if ca == nil || len(ca.Root) != 32 || len(ca.Signing) != 32 || ca.MapRevision < cert.NetworkRevision {
		return 0, false, false
	}
	remaining := max(0, cert.NotAfter.Sub(now))
	switch {
	case [32]byte(ca.Root) != cert.Root:
		return min(rootJitter, remaining/4), true, true
	case [32]byte(ca.Signing) != cert.Issuer:
		return min(signingJitter, remaining/4), true, false
	}
	return 0, false, false
}

// Action is what to do with Core's answer.
type Action uint8

// Actions (spec §6.9's reason table, design §10).
const (
	// ActionRetry sends the same request again.
	ActionRetry Action = iota + 1
	// ActionToken starts a new request with the pod's token.
	ActionToken
	// ActionWaitToken waits for the kubelet's next token, then a new token
	// request.
	ActionWaitToken
	// ActionWaitMap waits for a map that names a signing CA, then a new
	// request.
	ActionWaitMap
	// ActionNew starts a new request of the same proof.
	ActionNew
	// ActionNewKey starts a new request with a new key, after a growing
	// wait: the request itself was wrong.
	ActionNewKey
	// ActionStop asks no more for a while: the gateway may not ask.
	ActionStop
)

// actionFor maps a refusal's reason; a retry, and an outcome this build
// does not know, send the same request again; a refusal for a reason it does
// not know (Core's "internal") makes a new request after the refusal
// backoff: the same one would only be refused again (a4b1 review M1).
func actionFor(result controlplane.KubeCertResult) Action {
	if result.Outcome != controlplane.KubeCertRefused {
		return ActionRetry
	}
	switch result.Reason {
	case "proof", "renewal_unknown", "renewal_expired":
		return ActionToken
	case "token", "token_expired", "token_used", "trust_missing":
		return ActionWaitToken
	case "no_ca", "misnamed":
		return ActionWaitMap
	case "contested", "superseded", "attempts":
		return ActionNew
	case "csr", "conflict", "invalid":
		return ActionNewKey
	case "revoked", "cluster", "not_gateway", "not_proven":
		return ActionStop
	}
	return ActionNew
}

// fingerprint is the SHA-256 of a certificate's DER.
func fingerprint(der []byte) [32]byte { return sha256.Sum256(der) }
