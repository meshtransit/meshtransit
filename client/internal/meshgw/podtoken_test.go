package meshgw

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testToken(expiry time.Time, signature string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + strconv.FormatInt(expiry.Unix(), 10) + `}`))
	return "eyJhbGciOiJFUzI1NiJ9." + payload + "." + signature
}

func TestPodTokenSource(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "token")
	var logs bytes.Buffer
	source := podTokenSource(path, slog.New(slog.NewTextHandler(&logs, nil)), func() time.Time { return now })

	// No file: none, logged once.
	first, second := source(), source()
	if first != "" || second != "" || strings.Count(logs.String(), "kubernetes_pod_token_unavailable") != 1 {
		t.Fatalf("a missing file: %s", logs.String())
	}
	fresh := testToken(now.Add(8*time.Minute), "sig-fresh-aaaaaaaaaaaaaaaa")
	if err := os.WriteFile(path, []byte(fresh+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := source(); got.Reveal() != fresh || strings.Contains(logs.String(), "kubernetes_pod_token_stale") {
		t.Fatalf("a fresh token: %q, %s", got.Reveal(), logs.String())
	}
	healthy := testToken(now.Add(60*time.Second), "sig-healthy-cccccccccccccc")
	if err := os.WriteFile(path, []byte(healthy), 0o600); err != nil {
		t.Fatal(err)
	}
	source()
	if strings.Contains(logs.String(), "kubernetes_pod_token_stale") {
		t.Fatalf("a token kubelet may still rewrite in time: %s", logs.String())
	}
	stale := testToken(now.Add(20*time.Second), "sig-stale-bbbbbbbbbbbbbbbb")
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	source()
	source()
	if strings.Count(logs.String(), "kubernetes_pod_token_stale") != 1 || strings.Contains(logs.String(), stale) ||
		strings.Contains(logs.String(), fresh) {
		t.Fatalf("a stale token: %s", logs.String())
	}
}
