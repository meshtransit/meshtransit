package kubecert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"slices"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

// ErrVerify reports a certificate Core returned that the gateway does not
// take (§10 M6).
var ErrVerify = errors.New("kubecert: the issued certificate does not check")

// verify checks an issued answer for the key the request was made with,
// at now (Core's clock), against the map's CAs when the map is of the
// certificate's revision; it returns the certificate to keep (§10 M6):
//   - the leaf's public key is the request's key;
//   - the leaf is signed by chain[0], whose SHA-256 is the issuer named;
//   - the leaf is no CA and serves TLS servers (serverAuth);
//   - it is valid now, within the clock tolerance, for an hour at least;
//   - a map of the same revision names that issuer as the signing CA.
//
// The DNS name is checked by K1b, once the map names the cluster.
func verify(result controlplane.KubeCertResult, key *ecdsa.PrivateKey, ca *networkmap.KubernetesCA,
	now time.Time,
) (Certificate, error) {
	if key == nil || len(result.Chain) == 0 || len(result.RootFingerprint) != 32 ||
		len(result.IssuerFingerprint) != 32 {
		return Certificate{}, ErrVerify
	}
	leaf, err := x509.ParseCertificate(result.Certificate)
	if err != nil {
		return Certificate{}, errors.Join(ErrVerify, err)
	}
	issuer, err := x509.ParseCertificate(result.Chain[0])
	if err != nil {
		return Certificate{}, errors.Join(ErrVerify, err)
	}
	public, isECDSA := leaf.PublicKey.(*ecdsa.PublicKey)
	switch {
	case !isECDSA || !public.Equal(&key.PublicKey):
		return Certificate{}, errors.Join(ErrVerify, errors.New("another key"))
	case leaf.CheckSignatureFrom(issuer) != nil:
		return Certificate{}, errors.Join(ErrVerify, errors.New("not signed by the issuer named"))
	case fingerprint(result.Chain[0]) != [32]byte(result.IssuerFingerprint):
		return Certificate{}, errors.Join(ErrVerify, errors.New("the issuer is not the one named"))
	case leaf.IsCA || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth):
		return Certificate{}, errors.Join(ErrVerify, errors.New("not a TLS server certificate"))
	case now.Add(skew).Before(leaf.NotBefore) || leaf.NotAfter.Before(now.Add(time.Hour)):
		return Certificate{}, errors.Join(ErrVerify, errors.New("not valid now"))
	case leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128:
		return Certificate{}, errors.Join(ErrVerify, errors.New("a serial a renewal cannot name"))
	}
	// A map at or past the certificate's revision names the CA that signs
	// now: one issued by an older intermediate is not taken (a4b1 review
	// M2; design §10 M6).
	if ca != nil && ca.MapRevision >= result.NetworkRevision && len(ca.Signing) == 32 &&
		[32]byte(ca.Signing) != [32]byte(result.IssuerFingerprint) {
		return Certificate{}, errors.Join(ErrVerify, errors.New("the map names another signing CA"))
	}
	if ca != nil && ca.MapRevision >= result.NetworkRevision && len(ca.Root) == 32 &&
		[32]byte(ca.Root) != [32]byte(result.RootFingerprint) {
		return Certificate{}, errors.Join(ErrVerify, errors.New("the map names another root"))
	}
	cert := Certificate{
		Key: key, Leaf: leaf, DER: slices.Clone(result.Certificate), NotAfter: leaf.NotAfter,
		RenewAt: result.RenewAt, NetworkRevision: result.NetworkRevision, IssuedAt: now,
		Root: [32]byte(result.RootFingerprint), Issuer: [32]byte(result.IssuerFingerprint),
	}
	cert.Chain = make([][]byte, len(result.Chain))
	for index, der := range result.Chain {
		cert.Chain[index] = slices.Clone(der)
	}
	leaf.SerialNumber.FillBytes(cert.Serial[:])
	return cert, nil
}
