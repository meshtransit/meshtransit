package kubecluster

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

var (
	// ErrTrustChanged reports a replacement whose expected version is not
	// the trust's: another replacement or the first approval came first.
	ErrTrustChanged = errors.New("kubernetes cluster: the signing trust changed")
	// ErrIdentityBound reports a replacement that changes the namespace,
	// ServiceAccount or StatefulSet while a gateway runs or an approval may
	// still complete (K1.1b Q1).
	ErrIdentityBound = errors.New("kubernetes cluster: replicas still run under the cluster's identity")
)

// MaximumTrustReasonLength bounds the reason a replacement records, in
// characters.
const MaximumTrustReasonLength = 200

// TrustKey is one key of a cluster's signing trust: the kid its JWKS
// declares, the kid Kubernetes computes for it, its type and RFC 7638
// thumbprint. Kubectl shows the Kubernetes kid.
type TrustKey struct {
	KeyID           string
	KubernetesKeyID string
	Type            string
	Thumbprint      [32]byte
}

// TrustKeysOf names the keys of jwks, in its canonical order.
func TrustKeysOf(jwks kubejoin.JWKS) []TrustKey {
	keys := jwks.Keys()
	named := make([]TrustKey, 0, len(keys))
	for _, key := range keys {
		kind := "RSA"
		if key.Algorithm == kubejoin.AlgorithmES256 {
			kind = "EC"
		}
		named = append(named, TrustKey{KeyID: key.ID, KubernetesKeyID: key.KubernetesKeyID(), Type: kind,
			Thumbprint: key.Thumbprint})
	}
	return named
}

// KeyIDMismatches lists the declared kids that differ from the kid
// Kubernetes computes for their key: a pasted JWKS may label keys freely.
func KeyIDMismatches(keys []TrustKey) []string {
	var mismatched []string
	for _, key := range keys {
		if key.KeyID != key.KubernetesKeyID {
			mismatched = append(mismatched, key.KeyID)
		}
	}
	return mismatched
}

// TrustReplacement sets or replaces a cluster's signing trust from keys an
// administrator pasted (K1.1b). ExpectedVersion is the trust's version, 0
// when the cluster has none.
type TrustReplacement struct {
	Session         accountsession.Session
	Scope           network.Scope
	ClusterID       ID
	ExpectedVersion int64
	Issuer          string
	JWKS            kubejoin.JWKS
	Namespace       string
	ServiceAccount  string
	StatefulSet     string
	Reason          string
	CorrelationID   publicid.ID
}

// IsValid reports a replacement Core can store.
func (replacement TrustReplacement) IsValid() bool {
	return replacement.ClusterID.IsValid() && replacement.ExpectedVersion >= 0 &&
		kubejoin.ValidIssuer(replacement.Issuer) && !replacement.JWKS.IsZero() &&
		kubejoin.ValidNamespace(replacement.Namespace) && kubejoin.ValidName(replacement.ServiceAccount) &&
		kubejoin.ValidName(replacement.StatefulSet) && ValidTrustReason(replacement.Reason) &&
		replacement.CorrelationID.IsValid()
}

// ValidTrustReason reports a reason of 1 to 200 characters with no control
// character and no surrounding space.
func ValidTrustReason(reason string) bool {
	if !utf8.ValidString(reason) || reason != strings.TrimSpace(reason) {
		return false
	}
	count := utf8.RuneCountInString(reason)
	// Format characters (bidi overrides, zero widths) could disguise the text in the audit log.
	return count >= 1 && count <= MaximumTrustReasonLength && !strings.ContainsFunc(reason, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	})
}

// TrustReplacementResult is the trust after a replacement. Changed is false
// when the trust already was the one sent; Previous is the trust replaced,
// nil when the cluster had none or nothing changed.
type TrustReplacementResult struct {
	Changed  bool
	Trust    SigningTrust
	Previous *SigningTrust
}

// ReplaceTrust sets or replaces a cluster's signing trust; the store
// authorizes both kubernetes_cluster.manage and kubernetes_cluster.approve
// and records the audit event.
func (service *Service) ReplaceTrust(ctx context.Context, replacement TrustReplacement) (TrustReplacementResult,
	error) {
	if err := service.admit(ctx, replacement.Session, replacement.Scope); err != nil {
		return TrustReplacementResult{}, err
	}
	if !replacement.IsValid() {
		return TrustReplacementResult{}, ErrInvalid
	}
	return service.store.ReplaceSigningTrust(ctx, replacement)
}
