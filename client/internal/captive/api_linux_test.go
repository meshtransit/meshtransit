package captive

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestAPIURIsReadsNetworkdLinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, text := range map[string]string{
		"2": "ADMIN_STATE=configured\nCAPTIVE_PORTAL=https://portal.example/api\n",
		"3": "CAPTIVE_PORTAL=http://plain.example/api\n",
		"4": "CAPTIVE_PORTAL=https://portal.example/api\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := apiURIsIn(dir); !slices.Equal(got, []string{"https://portal.example/api"}) {
		t.Fatalf("apiURIsIn() = %v", got)
	}
	if got := apiURIsIn(filepath.Join(dir, "absent")); got != nil {
		t.Fatalf("apiURIsIn(absent) = %v", got)
	}
}
