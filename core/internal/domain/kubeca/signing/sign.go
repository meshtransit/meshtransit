package signing

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	// cacheLifetime bounds how long an opened intermediate stays in memory
	// (review L7).
	cacheLifetime = 5 * time.Minute
	// maximumCached bounds the opened intermediates kept.
	maximumCached = 256
	serialBytes   = 16
	// unusableLifetime is how long a CA that did not open is not tried
	// again: its requests are refused at once (review a3a H1).
	unusableLifetime = time.Minute
)

// RenewalVerifier checks a renewal signature (shared/mtcp, injected so the
// domain stays free of protocol code).
type RenewalVerifier func(publicKey []byte, handshakeHash [32]byte, requestID, serial [16]byte, csr,
	proof []byte) bool

// decision is what to do with a claim: issue it, or refuse it for reason.
type decision struct {
	issue  Issue
	refuse Reason
}

type cacheKey struct {
	ca      publicid.ID
	version int64
}

type cachedCA struct {
	ca    kubeca.CA
	until time.Time
}

// signer signs claims of one installation. It is owned by one goroutine.
type signer struct {
	installation  deployment.ID
	suffix        dnsname.Suffix
	verifyToken   TokenVerifier
	verifyRenewal RenewalVerifier
	cache         map[cacheKey]cachedCA
	unusable      map[cacheKey]time.Time
}

func newSigner(installation deployment.ID, suffix dnsname.Suffix, verifyToken TokenVerifier,
	verifyRenewal RenewalVerifier,
) *signer {
	return &signer{
		installation: installation, suffix: suffix, verifyToken: verifyToken, verifyRenewal: verifyRenewal,
		cache: map[cacheKey]cachedCA{}, unusable: map[cacheKey]time.Time{},
	}
}

// sign decides a claim at now (the database's clock at claim): refused, or
// signed and ready to issue. An error is the worker's own trouble (custody,
// a CA it cannot open, entropy): the claim is given back.
func (signer *signer) sign(ctx context.Context, custody kubeca.Custody, claim Claim, now time.Time) (decision,
	error,
) {
	intermediate := claim.Intermediate
	if intermediate == nil || intermediate.NotAfter.Sub(now) < kubeca.MinimumSigningLife {
		return decision{refuse: ReasonNoCA}, nil
	}
	// The name is computed from the database, never taken from the CA, so
	// an intermediate under another name signs nothing (review M7).
	name, ok := clusterDNSName(claim, signer.suffix)
	if !ok || name != intermediate.ClusterDNSName {
		return decision{refuse: ReasonMisnamed}, nil
	}
	var token *TokenUse
	var trustVersion int64
	switch claim.Proof {
	case ProofToken:
		// The worker checked the token at its first claim (checkToken) and
		// recorded what it checked (§14 R-M1).
		verified := claim.Verified
		if verified == nil || !verified.Valid() {
			return decision{refuse: ReasonToken}, nil
		}
		if !verified.Use.ExpiresAt.After(now) {
			return decision{refuse: ReasonTokenExpired}, nil
		}
		if claim.Trust == nil || claim.Trust.Version != verified.TrustVersion {
			return decision{refuse: ReasonTrustMissing}, nil
		}
		use := verified.Use
		token, trustVersion = &use, verified.TrustVersion
	case ProofRenewal:
		if len(claim.RenewalPublicKey) == 0 || !claim.RenewalNotAfter.After(now) {
			return decision{refuse: ReasonRenewalExpired}, nil
		}
		if !signer.verifyRenewal(claim.RenewalPublicKey, claim.HandshakeHash, claim.RequestID, claim.RenewalSerial,
			claim.CSR, claim.RenewalProof) {
			return decision{refuse: ReasonProof}, nil
		}
	default:
		return decision{refuse: ReasonProof}, nil
	}
	ca, err := signer.open(ctx, custody, claim, now)
	if err != nil {
		return decision{}, err
	}
	issued, err := ca.SignReplica(kubeca.ReplicaRequest{CSR: claim.CSR, ClusterDNSName: name, Now: now})
	if errors.Is(err, kubeca.ErrInvalid) {
		return decision{refuse: ReasonCSR}, nil
	}
	if err != nil {
		return decision{}, err
	}
	if issued.PublicKeySHA256 != claim.PublicKeySHA256 {
		return decision{refuse: ReasonCSR}, nil
	}
	certificate, err := x509.ParseCertificate(issued.Certificate)
	if err != nil || issued.Serial == nil || issued.Serial.BitLen() > 8*serialBytes {
		return decision{}, kubeca.ErrInvalid
	}
	id, err := publicid.New()
	if err != nil {
		return decision{}, err
	}
	renewAt, err := renewalTime(now, issued.NotAfter)
	if err != nil {
		return decision{}, err
	}
	return decision{issue: Issue{
		Request: claim.ID, ClaimToken: claim.ClaimToken, ID: id, CA: intermediate.ID,
		CAVersion: intermediate.Version, Serial: issued.Serial.FillBytes(make([]byte, serialBytes)),
		Certificate: issued.Certificate, PublicKey: certificate.RawSubjectPublicKeyInfo,
		NotBefore: issued.NotBefore, NotAfter: issued.NotAfter, RenewAt: renewAt, Token: token,
		TrustVersion: trustVersion,
	}}, nil
}

// clusterDNSName is <cluster>.kube.<workspace>.<network>.<suffix>.
func clusterDNSName(claim Claim, suffix dnsname.Suffix) (string, bool) {
	workspaceCode, workspaceErr := identity.ParseDisplayCode(claim.WorkspaceCode)
	networkCode, networkErr := identity.ParseDisplayCode(claim.NetworkCode)
	if workspaceErr != nil || networkErr != nil {
		return "", false
	}
	zone, err := dnsname.NewZone(workspaceCode, networkCode, suffix)
	if err != nil {
		return "", false
	}
	return zone.KubernetesClusterName(claim.ClusterName)
}

// checkToken checks a token request's pod token against its cluster's
// signing trust at now: the claims to record in its place, or why it is
// refused.
func (signer *signer) checkToken(claim Claim, now time.Time) (VerifiedToken, Reason) {
	if claim.Trust == nil || !claim.Trust.Complete() {
		return VerifiedToken{}, ReasonTrustMissing
	}
	use, err := signer.verifyToken(claim.Token, *claim.Trust, now)
	if err != nil || !validJTI(use.JTI) || !use.ExpiresAt.After(now) || use.PodName != claim.Trust.PodName ||
		!validPodName(use.PodName) {
		return VerifiedToken{}, ReasonToken
	}
	// A token's expiry is whole seconds (JWT exp); recorded as such, the
	// claims read back equal the ones checked.
	use.ExpiresAt = use.ExpiresAt.Truncate(time.Second)
	return VerifiedToken{Use: use, TrustVersion: claim.Trust.Version}, ""
}

// validJTI reports a jti the ledger keeps: 1 to 128 printable ASCII
// characters (schema 240, 241).
func validJTI(jti string) bool {
	if len(jti) == 0 || len(jti) > 128 {
		return false
	}
	for index := range len(jti) {
		if jti[index] < '!' || jti[index] > '~' {
			return false
		}
	}
	return true
}

// validPodName reports a pod name the ledger keeps: a DNS subdomain.
func validPodName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' &&
			character != '-' {
			return false
		}
	}
	return true
}

// renewalTime is when the gateway renews: a third of the way into the
// certificate's life, give or take a twenty-fourth at random so a cluster's
// replicas spread out. A 24-hour certificate renews 7 to 9 hours after it
// is issued, so signing may stop for about 15 hours before a running
// replica's certificate expires (§14 R-H1, design §15.9).
func renewalTime(now, notAfter time.Time) (time.Time, error) {
	life := notAfter.Sub(now)
	if life <= 0 {
		return time.Time{}, kubeca.ErrInvalid
	}
	spread := life / 24
	jitter := time.Duration(0)
	if spread > 0 {
		value, err := rand.Int(rand.Reader, big.NewInt(2*int64(spread)+1))
		if err != nil {
			return time.Time{}, err
		}
		jitter = time.Duration(value.Int64()) - spread
	}
	return now.Add(life/3 + jitter), nil
}

// open returns the claim's intermediate in the clear, opened at most every
// five minutes for a given CA version.
func (signer *signer) open(ctx context.Context, custody kubeca.Custody, claim Claim, now time.Time) (kubeca.CA,
	error,
) {
	intermediate := claim.Intermediate
	key := cacheKey{ca: intermediate.ID, version: intermediate.Version}
	if cached, ok := signer.cache[key]; ok && now.Before(cached.until) {
		return cached.ca, nil
	}
	if custody == nil {
		return kubeca.CA{}, kubeca.ErrUnavailable
	}
	if until, ok := signer.unusable[key]; ok && now.Before(until) {
		return kubeca.CA{}, errCAUnusable
	}
	ca, err := signer.openIntermediate(ctx, custody, claim)
	if err != nil {
		if !custodyFailure(err) && len(signer.unusable) < maximumCached {
			signer.unusable[key] = now.Add(unusableLifetime)
		}
		return kubeca.CA{}, err
	}
	signer.forget(now)
	if len(signer.cache) < maximumCached {
		signer.cache[key] = cachedCA{ca: ca, until: now.Add(cacheLifetime)}
	}
	return ca, nil
}

func (signer *signer) openIntermediate(ctx context.Context, custody kubeca.Custody, claim Claim) (kubeca.CA,
	error,
) {
	intermediate := claim.Intermediate
	root, err := x509.ParseCertificate(intermediate.RootCertificate)
	if err != nil {
		return kubeca.CA{}, kubeca.ErrInvalid
	}
	dataKey, err := custody.OpenDataKey(ctx, claim.Scope.NetworkID().String(), intermediate.DataKey.Wrapped)
	if err != nil {
		return kubeca.CA{}, err
	}
	return kubeca.OpenIntermediate(dataKey, intermediate.Certificate, intermediate.SealedKey,
		signer.installation.String(), claim.ClusterID.String(), intermediate.ID.String(), root)
}

// errCAUnusable reports a CA that did not open a moment ago.
var errCAUnusable = errors.New("kubernetes certificate signer: the cluster CA does not open")

// forget drops expired intermediates and expired marks of unusable ones.
func (signer *signer) forget(now time.Time) {
	for key, cached := range signer.cache {
		if !now.Before(cached.until) {
			delete(signer.cache, key)
		}
	}
	for key, until := range signer.unusable {
		if !now.Before(until) {
			delete(signer.unusable, key)
		}
	}
}

// clear drops every opened intermediate (a restore suspected, the worker
// stopping).
func (signer *signer) clear() {
	clear(signer.cache)
}

// drop forgets every version of a CA (it changed while it signed).
func (signer *signer) drop(ca publicid.ID) {
	for key := range signer.cache {
		if key.ca == ca {
			delete(signer.cache, key)
		}
	}
}
