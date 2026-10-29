package meshgw

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeAPIToken writes a token whose claims are claims.
func writeAPIToken(t *testing.T, claims string) (path, encodedClaims string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "token")
	encodedClaims = base64.RawURLEncoding.EncodeToString([]byte(claims))
	if err := os.WriteFile(path, []byte("eyJhbGciOiJSUzI1NiJ9."+encodedClaims+".c2ln\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, encodedClaims
}

// MESHGW_API_AUDIENCES is a comma list of audiences; spaces, JSON and
// repeats are refused.
func TestLoadConfigAPIAudiences(t *testing.T) {
	t.Parallel()
	env := proxyEnv(t)
	env["MESHGW_API_AUDIENCES"] = "https://kubernetes.default.svc, api"
	cfg, err := loadFrom(env)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Kube.APIAudiences, []string{"https://kubernetes.default.svc", "api"}) {
		t.Fatalf("APIAudiences = %q", cfg.Kube.APIAudiences)
	}
	for _, bad := range []string{"a b", `["https://kubernetes.default.svc"]`, "a,a"} {
		env["MESHGW_API_AUDIENCES"] = bad
		if _, err := loadFrom(env); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// A token naming other audiences than the chart's is reported once, with
// the value to set, never the token; the audiences come back for status.
func TestCheckAudiences(t *testing.T) {
	t.Parallel()
	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	path, encoded := writeAPIToken(t, `{"aud":["https://kubernetes.default.svc"]}`)
	got := checkAudiences(KubeConfig{
		APITokenFile: path,
		APIAudiences: []string{"https://kubernetes.default.svc.cluster.local"},
	}, logger)
	if !slices.Equal(got, []string{"https://kubernetes.default.svc"}) ||
		!strings.Contains(logged.String(), "kubernetes_audience_mismatch") {
		t.Fatalf("%q; log %s", got, logged.String())
	}
	for _, part := range []string{"eyJhbGci", encoded, "c2ln"} {
		if strings.Contains(logged.String(), part) {
			t.Fatalf("the token was logged: %s", logged.String())
		}
	}
	logged.Reset()
	checkAudiences(KubeConfig{APITokenFile: path, APIAudiences: []string{"https://kubernetes.default.svc"}}, logger)
	if logged.Len() != 0 {
		t.Fatalf("same audiences logged %s", logged.String())
	}
	gateway, _ := writeAPIToken(t, `{"aud":["meshtransit.net/kubernetes-gateway"]}`)
	if got := checkAudiences(KubeConfig{APITokenFile: gateway, APIAudiences: []string{"x"}}, logger); got != nil ||
		!strings.Contains(logged.String(), "kubernetes_audiences_unknown") ||
		strings.Contains(logged.String(), "kubernetes_audience_mismatch") {
		t.Fatalf("the gateway's token: %q; log %s", got, logged.String())
	}
}

// /status carries the API server's audiences when known, and omits them
// when not.
func TestKubeStatusAudiences(t *testing.T) {
	t.Parallel()
	known, _ := jsonOf(t, kubeStatus{Mode: KubeModeProxy, APIAudiences: []string{"a"}})
	unknown, _ := jsonOf(t, kubeStatus{Mode: KubeModeProxy})
	if !strings.Contains(known, `"api_audiences":["a"]`) || strings.Contains(unknown, "api_audiences") {
		t.Fatalf("known %s, unknown %s", known, unknown)
	}
}

func jsonOf(t *testing.T, value any) (string, error) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded), nil
}
