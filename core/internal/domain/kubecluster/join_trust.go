package kubecluster

import (
	"errors"
	"slices"

	"meshtransit.net/shared/kubejoin"
)

var (
	// ErrJoinAgain reports a request opened without signing material (before
	// K1.1, or by an older Core): it is never approved or completed, and the
	// replica must join again.
	ErrJoinAgain = errors.New("kubernetes cluster: the replica must join again with its signing keys")
	// ErrSigningMismatch reports a replica whose issuer, ServiceAccount or
	// StatefulSet differs from the cluster's trust, or whose token was signed
	// by a key the trust does not hold.
	ErrSigningMismatch = errors.New("kubernetes cluster: the replica's signing keys differ from the cluster's")
	// ErrPodHeld reports a pod that a live gateway Device or another approval
	// already holds.
	ErrPodHeld = errors.New("kubernetes cluster: a Device already holds the pod")
)

// JoinTrust is the ServiceAccount signing material a replica's pod sent
// with its join and Core verified (K1.1 design §6.2): the cluster's issuer
// and keys, the namespace, ServiceAccount and pod its token named, the key
// that signed the token, and the digest the join code v2 binds. Only
// NewJoinTrust makes a valid one.
type JoinTrust struct {
	issuer            string
	jwks              []byte
	keyThumbprints    [][32]byte
	namespace         string
	serviceAccount    string
	statefulSet       string
	podName           string
	joinKeyThumbprint [32]byte
	digest            [32]byte
}

// NewJoinTrust takes trust whose token Core verified with the key whose
// thumbprint is joinKeyThumbprint, one of trust's keys.
func NewJoinTrust(trust kubejoin.Trust, joinKeyThumbprint [32]byte) (JoinTrust, error) {
	digest, err := kubejoin.TrustDigest(trust)
	if err != nil {
		return JoinTrust{}, ErrInvalid
	}
	statefulSet, ok := kubejoin.StatefulSetOf(trust.PodName)
	if !ok {
		return JoinTrust{}, ErrInvalid
	}
	keys := trust.JWKS.Keys()
	thumbprints := make([][32]byte, 0, len(keys))
	for _, key := range keys {
		thumbprints = append(thumbprints, key.Thumbprint)
	}
	if !slices.Contains(thumbprints, joinKeyThumbprint) {
		return JoinTrust{}, ErrInvalid
	}
	return JoinTrust{
		issuer: trust.Issuer, jwks: trust.JWKS.Canonical(), keyThumbprints: thumbprints,
		namespace: trust.Namespace, serviceAccount: trust.ServiceAccount, statefulSet: statefulSet,
		podName: trust.PodName, joinKeyThumbprint: joinKeyThumbprint, digest: digest,
	}, nil
}

// IsValid reports whether NewJoinTrust made the trust.
func (trust JoinTrust) IsValid() bool { return trust.digest != [32]byte{} }

// Issuer returns the cluster's issuer.
func (trust JoinTrust) Issuer() string { return trust.issuer }

// JWKS returns a copy of the cluster's keys in canonical form.
func (trust JoinTrust) JWKS() []byte { return slices.Clone(trust.jwks) }

// KeyThumbprints returns a copy of the keys' RFC 7638 thumbprints.
func (trust JoinTrust) KeyThumbprints() [][32]byte { return slices.Clone(trust.keyThumbprints) }

// Namespace returns the pod's namespace.
func (trust JoinTrust) Namespace() string { return trust.namespace }

// ServiceAccount returns the pod's ServiceAccount.
func (trust JoinTrust) ServiceAccount() string { return trust.serviceAccount }

// StatefulSet returns the StatefulSet the pod belongs to.
func (trust JoinTrust) StatefulSet() string { return trust.statefulSet }

// PodName returns the pod's name.
func (trust JoinTrust) PodName() string { return trust.podName }

// JoinKeyThumbprint returns the thumbprint of the key that signed the
// join's token.
func (trust JoinTrust) JoinKeyThumbprint() [32]byte { return trust.joinKeyThumbprint }

// Digest returns the trust digest the join code v2 binds.
func (trust JoinTrust) Digest() [32]byte { return trust.digest }
