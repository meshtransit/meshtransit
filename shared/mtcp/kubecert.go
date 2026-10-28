package mtcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

const (
	kubeCertRenewalDomain = "meshtransit/kube-cert-renewal/v1"
	// KubeCertRenewalProofMaximum bounds a renewal proof: an ASN.1 ECDSA
	// P-256 signature.
	KubeCertRenewalProofMaximum = 72
	// KubeCertRenewalProofMinimum bounds it below: an ASN.1 sequence of two
	// integers takes at least 8 bytes.
	KubeCertRenewalProofMinimum = 8
	// KubeCertChainMaximum bounds the intermediates a KubeCertResult
	// carries.
	KubeCertChainMaximum = 4
	// KubeCertCSRMaximum bounds a KubeCertRequest's CSR.
	KubeCertCSRMaximum = 4096
	// KubeCertRequestIDSize is the size of a request ID.
	KubeCertRequestIDSize = 16
	// KubeCertSerialSize is the size of a replica certificate's serial.
	KubeCertSerialSize = 16
)

// ErrKubeCertRenewalKey reports a key that cannot make a renewal proof.
var ErrKubeCertRenewalKey = errors.New("mtcp: a renewal proof needs a P-256 key")

// kubeCertRenewalDigest is SHA-256(domain || 0x00 || h || request_id ||
// renewal_serial || SHA-256(csr)): the proof binds the session, the request,
// the certificate renewed (a3 §14 R-L1) and the CSR.
func kubeCertRenewalDigest(handshakeHash [32]byte, requestID [16]byte, serial [16]byte,
	csr []byte,
) [sha256.Size]byte {
	csrHash := sha256.Sum256(csr)
	message := make([]byte, 0, len(kubeCertRenewalDomain)+1+32+16+16+sha256.Size)
	message = append(message, kubeCertRenewalDomain...)
	message = append(message, 0)
	message = append(message, handshakeHash[:]...)
	message = append(message, requestID[:]...)
	message = append(message, serial[:]...)
	message = append(message, csrHash[:]...)
	return sha256.Sum256(message)
}

// SignKubeCertRenewal makes a gateway's renewal proof (mtcp-v1 §6.9): a
// signature with the key of its current certificate, which only the pod
// holds in memory.
func SignKubeCertRenewal(current *ecdsa.PrivateKey, handshakeHash [32]byte, requestID, serial [16]byte,
	csr []byte,
) ([]byte, error) {
	if current == nil || current.Curve != elliptic.P256() {
		return nil, ErrKubeCertRenewalKey
	}
	digest := kubeCertRenewalDigest(handshakeHash, requestID, serial, csr)
	return ecdsa.SignASN1(rand.Reader, current, digest[:])
}

// VerifyKubeCertRenewal checks a renewal proof against the public key
// (PKIX DER) and serial of the certificate being renewed.
func VerifyKubeCertRenewal(publicKey []byte, handshakeHash [32]byte, requestID, serial [16]byte, csr,
	proof []byte,
) bool {
	if len(proof) < KubeCertRenewalProofMinimum || len(proof) > KubeCertRenewalProofMaximum {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return false
	}
	digest := kubeCertRenewalDigest(handshakeHash, requestID, serial, csr)
	return ecdsa.VerifyASN1(key, digest[:], proof)
}
