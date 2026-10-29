// Package kubetrust checks what a node trusts a Kubernetes cluster's
// gateways by: the cluster's roots, as its map names them (mtcp-v1 §7.11,
// K1a4d design §6).
package kubetrust

import (
	"crypto/x509"
	"errors"
	"net"
	"strings"
)

// Bounds of a cluster DNS name, as Core's CAs take it.
const (
	maximumName  = 253
	maximumLabel = 63
)

// Reasons a root is left out of its cluster's trust.
var (
	// ErrMalformed: the DER is not a certificate.
	ErrMalformed = errors.New("kubetrust: the root does not parse")
	// ErrNotARoot: not a self-signed CA with every constraint Core's roots
	// carry (path length 1, one critical permitted DNS name, every IP
	// address excluded, nothing else).
	ErrNotARoot = errors.New("kubetrust: not a cluster root")
	// ErrOtherName: the root permits a name other than the cluster's.
	ErrOtherName = errors.New("kubetrust: the root permits another name")
)

// CheckRoot parses a cluster's root and checks it is one Core makes, for
// the TLS name the cluster's gateways' certificates carry. The key type is
// not checked here: the node checks it where it uses the root (K1e).
func CheckRoot(der []byte, name string) (*x509.Certificate, error) {
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Join(ErrMalformed, err)
	}
	if !constrainedRoot(root) || root.CheckSignatureFrom(root) != nil {
		return nil, ErrNotARoot
	}
	if root.PermittedDNSDomains[0] != name {
		return nil, ErrOtherName
	}
	return root, nil
}

// constrainedRoot mirrors the core's constrainedCA at path length 1, and
// refuses what Core never sets (extended key usage, excluded mail or URI
// names, critical extensions Go does not handle).
func constrainedRoot(certificate *x509.Certificate) bool {
	return certificate.IsCA && certificate.BasicConstraintsValid && certificate.MaxPathLen == 1 &&
		!certificate.MaxPathLenZero && certificate.KeyUsage == x509.KeyUsageCertSign|x509.KeyUsageCRLSign &&
		certificate.PermittedDNSDomainsCritical && len(certificate.PermittedDNSDomains) == 1 &&
		ValidName(certificate.PermittedDNSDomains[0]) && len(certificate.PermittedIPRanges) == 0 &&
		len(certificate.ExcludedIPRanges) == 2 && excludesEveryAddress(certificate.ExcludedIPRanges) &&
		len(certificate.ExcludedDNSDomains) == 0 && len(certificate.PermittedEmailAddresses) == 0 &&
		len(certificate.ExcludedEmailAddresses) == 0 && len(certificate.PermittedURIDomains) == 0 &&
		len(certificate.ExcludedURIDomains) == 0 && len(certificate.ExtKeyUsage) == 0 &&
		len(certificate.UnknownExtKeyUsage) == 0 && len(certificate.UnhandledCriticalExtensions) == 0
}

func excludesEveryAddress(ranges []*net.IPNet) bool {
	v4, v6 := false, false
	for _, excluded := range ranges {
		ones, bits := excluded.Mask.Size()
		v4 = v4 || ones == 0 && bits == 32
		v6 = v6 || ones == 0 && bits == 128
	}
	return v4 && v6
}

// ValidName reports a cluster DNS name as Core's CAs take it: lowercase
// labels of letters, digits and inner hyphens.
func ValidName(name string) bool {
	if name == "" || len(name) > maximumName {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > maximumLabel || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
