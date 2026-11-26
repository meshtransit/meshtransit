package selfhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresMajorFollowsTheImage(t *testing.T) {
	t.Parallel()
	if got := PostgresMajor(); got != "18" {
		t.Fatalf("PostgresMajor() = %q for %s", got, postgresImage)
	}
}

func TestCheckPostgresMajorRefusesAnotherMajor(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	if err := CheckPostgresMajor(stateDir); err != nil {
		t.Fatalf("new install: %v", err)
	}
	data := filepath.Join(stateDir, "postgres", "pgdata")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckPostgresMajor(stateDir); err != nil {
		t.Fatalf("data directory before initdb: %v", err)
	}
	for version, want := range map[string]error{"18\n": nil, "17\n": ErrPostgresMajorMismatch, "19": ErrPostgresMajorMismatch} {
		if err := os.WriteFile(filepath.Join(data, "PG_VERSION"), []byte(version), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckPostgresMajor(stateDir); !errors.Is(err, want) {
			t.Errorf("PG_VERSION %q: %v, want %v", version, err, want)
		}
	}
}
