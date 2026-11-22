package kubecheck

import (
	"context"
	"encoding/hex"

	"meshtransit.net/shared/kubejoin"
)

// Info is a finding that reports, neither failing nor warning: the cluster
// trust digest an administrator compares before confirming (V1-12 §3.4).
const Info Level = "info"

// trustDigest reports the cluster trust digest of the issuer and keys the
// API server serves, for the gateway's namespace, ServiceAccount and
// StatefulSet (kubejoin.ClusterTrustDigest): the Console shows the digest
// an install token pinned, and an administrator confirms it only when the
// two match. The check never sends it anywhere.
func (checker Checker) trustDigest(ctx context.Context, report *Report) {
	if checker.Signing == nil {
		return
	}
	issuer, raw, err := checker.Signing(ctx)
	if err != nil {
		report.add(Warn, "trust_digest_unavailable",
			"the cluster's issuer and keys could not be read to print the trust digest: %s", printable(err.Error()))
		return
	}
	jwks, err := kubejoin.ParseJWKS(raw)
	if err != nil {
		report.add(Warn, "trust_digest_unavailable", "the cluster's keys are not accepted: %s",
			printable(err.Error()))
		return
	}
	digest, err := kubejoin.ClusterTrustDigest(kubejoin.Trust{Issuer: issuer, JWKS: jwks,
		Namespace: checker.Config.Namespace, ServiceAccount: checker.Config.ServiceAccount,
		PodName: checker.Config.StatefulSet + "-0"})
	if err != nil {
		report.add(Warn, "trust_digest_unavailable", "the cluster's issuer or names give no trust digest")
		return
	}
	report.add(Info, "trust_digest", "%s (compare it with the trust digest on the cluster's page before you "+
		"confirm)", hex.EncodeToString(digest[:]))
}
