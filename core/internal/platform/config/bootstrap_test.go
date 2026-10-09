package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBootstrapPlan(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(`{"format":"meshtransit-bootstrap/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	contents, err := LoadBootstrapPlan(mapLookup(map[string]string{envBootstrapPlanFile: path}))
	if err != nil || string(contents) != `{"format":"meshtransit-bootstrap/v1"}` {
		t.Fatalf("plan = %q, %v", contents, err)
	}
	for name, values := range map[string]map[string]string{
		"missing":  {},
		"relative": {envBootstrapPlanFile: "plan.json"},
		"absent":   {envBootstrapPlanFile: filepath.Join(t.TempDir(), "missing.json")},
	} {
		if _, err := LoadBootstrapPlan(mapLookup(values)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}
