package kubecluster_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

// kindJWKS is the JWKS kind meshgw-a served on 2026-10-27: its kid is the
// one Kubernetes computes.
const kindJWKS = `{"keys":[{"use":"sig","kty":"RSA","kid":"W5g6JhuNGLKpWbGKkY1h_vyNJWNV3OHpeiEJLThDJhE","alg":"RS256","n":"ulb6f8XOFK8q2EKPjPXlwDQuMhPTiee6zlEDZu0twbQecr0w7uG6Vqghhovln3lwCtJdM_eHsWfgmd6I-HdaFUv738BlNvEZXanR9d5mSBmnIDtIUTpwrNOVTuskzBOMceJf86g7QwfL_ixA8xaavgt27B5dqZJcM34ORUy6O2qcm18keFqKhMoQ_FPnFS1xZmEPTw3VzBLpOAaI6sTh0-LBTtszztX-F6GYSw3bZenJUVQ9CHAPr4AtJRrRA0lpZj__gCz9CpajdNfJY712HzBv6tMb8ElqO3DaEr2ka40yqIug9wkMmlLg85MrMhtOZViuZq0hf_SAPFipqjVQKw","e":"AQAB"}]}`

func mustJWKS(t *testing.T, raw string) kubejoin.JWKS {
	t.Helper()
	jwks, err := kubejoin.ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return jwks
}

// Each key is named by its declared kid and the one Kubernetes computes; a
// difference is listed.
func TestTrustKeysNameEachKey(t *testing.T) {
	t.Parallel()
	keys := kubecluster.TrustKeysOf(mustJWKS(t, kindJWKS))
	if len(keys) != 1 || keys[0].KeyID != keys[0].KubernetesKeyID || keys[0].Type != "RSA" ||
		keys[0].Thumbprint == ([32]byte{}) {
		t.Fatalf("TrustKeysOf() = %+v", keys)
	}
	if mismatched := kubecluster.KeyIDMismatches(keys); len(mismatched) != 0 {
		t.Fatalf("KeyIDMismatches() = %v", mismatched)
	}
	renamed := kubecluster.TrustKeysOf(mustJWKS(t, strings.Replace(kindJWKS, keys[0].KeyID, "other", 1)))
	if mismatched := kubecluster.KeyIDMismatches(renamed); len(mismatched) != 1 || mismatched[0] != "other" {
		t.Fatalf("KeyIDMismatches(renamed) = %v", mismatched)
	}
}

// A replacement needs an https issuer, valid names and a reason of 1 to 200
// characters without control characters or padding; it never reaches the
// store otherwise.
func TestServiceReplaceTrustAdmission(t *testing.T) {
	t.Parallel()
	service, store, session, scope, _ := serviceFixture(t)
	replacement := kubecluster.TrustReplacement{Session: session, Scope: scope,
		ClusterID: kubecluster.ID(mustID(t, "000000000301")), ExpectedVersion: 1,
		Issuer: "https://kubernetes.default.svc.cluster.local", JWKS: mustJWKS(t, kindJWKS),
		Namespace: "mt-kube-k1", ServiceAccount: "meshgw", StatefulSet: "meshgw",
		Reason: "kind rotated its signing key", CorrelationID: mustID(t, "000000000901")}
	if _, err := service.ReplaceTrust(context.Background(), replacement); err != nil {
		t.Fatalf("ReplaceTrust() error = %v", err)
	}
	for name, change := range map[string]func(*kubecluster.TrustReplacement){
		"no cluster":        func(r *kubecluster.TrustReplacement) { r.ClusterID = kubecluster.ID{} },
		"negative version":  func(r *kubecluster.TrustReplacement) { r.ExpectedVersion = -1 },
		"http issuer":       func(r *kubecluster.TrustReplacement) { r.Issuer = "http://kubernetes.default.svc" },
		"no keys":           func(r *kubecluster.TrustReplacement) { r.JWKS = kubejoin.JWKS{} },
		"bad namespace":     func(r *kubecluster.TrustReplacement) { r.Namespace = "Mt_Kube" },
		"bad account":       func(r *kubecluster.TrustReplacement) { r.ServiceAccount = "" },
		"bad statefulset":   func(r *kubecluster.TrustReplacement) { r.StatefulSet = "a/b" },
		"no reason":         func(r *kubecluster.TrustReplacement) { r.Reason = "" },
		"padded reason":     func(r *kubecluster.TrustReplacement) { r.Reason = " why" },
		"long reason":       func(r *kubecluster.TrustReplacement) { r.Reason = strings.Repeat("é", 201) },
		"control reason":    func(r *kubecluster.TrustReplacement) { r.Reason = "a\nb" },
		"C1 reason":         func(r *kubecluster.TrustReplacement) { r.Reason = "a\u0085b" },
		"bidi reason":       func(r *kubecluster.TrustReplacement) { r.Reason = "a\u202eb" },
		"zero-width reason": func(r *kubecluster.TrustReplacement) { r.Reason = "a\u200bb" },
		"no correlation":    func(r *kubecluster.TrustReplacement) { r.CorrelationID = publicid.ID{} },
	} {
		invalid := replacement
		change(&invalid)
		if _, err := service.ReplaceTrust(context.Background(), invalid); !errors.Is(err, kubecluster.ErrInvalid) {
			t.Errorf("%s: ReplaceTrust() error = %v, want ErrInvalid", name, err)
		}
	}
	if len(store.replacements) != 1 {
		t.Fatalf("store calls = %d, want 1", len(store.replacements))
	}
}
