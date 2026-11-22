package kubecheck

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/shared/kubejoin"
)

const trustTestJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"fixture",` +
	`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`

// helm test prints the cluster trust digest Core computes for the
// gateway's StatefulSet, never failing or warning for it.
func TestTrustDigestFinding(t *testing.T) {
	t.Parallel()
	const issuer = "https://kubernetes.default.svc.cluster.local"
	checker := Checker{Config: Config{Namespace: "mt-kube-k1", StatefulSet: "meshgw", ServiceAccount: "meshgw"},
		Signing: func(context.Context) (string, []byte, error) { return issuer, []byte(trustTestJWKS), nil }}
	var report Report
	checker.trustDigest(context.Background(), &report)
	jwks, err := kubejoin.ParseJWKS([]byte(trustTestJWKS))
	if err != nil {
		t.Fatal(err)
	}
	want, err := kubejoin.ClusterTrustDigest(kubejoin.Trust{Issuer: issuer, JWKS: jwks, Namespace: "mt-kube-k1",
		ServiceAccount: "meshgw", PodName: "meshgw-3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Level != Info || report.Findings[0].Code != "trust_digest" ||
		!strings.HasPrefix(report.Findings[0].Message, hex.EncodeToString(want[:])) || report.Failed() {
		t.Fatalf("findings %+v", report.Findings)
	}
	if summary := report.Summary(); !strings.HasPrefix(summary, "0 failed, 0 warnings\n") ||
		!strings.Contains(summary, "info trust_digest: "+hex.EncodeToString(want[:])) {
		t.Fatalf("summary %q", summary)
	}
	checker.Signing = func(context.Context) (string, []byte, error) { return "", nil, errors.New("forbidden") }
	report = Report{}
	checker.trustDigest(context.Background(), &report)
	if len(report.Findings) != 1 || report.Findings[0].Level != Warn || report.Failed() {
		t.Fatalf("unreadable keys: %+v", report.Findings)
	}
}
