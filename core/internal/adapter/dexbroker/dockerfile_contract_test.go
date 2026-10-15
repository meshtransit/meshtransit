package dexbroker_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The broker-capable image builds the same MeshCore binary as core/Dockerfile,
// with Dex linked in. Its build stage must copy every source tree the plain
// build copies, or the image cannot be built from the repository (it once
// lacked shared/).
func TestDexbrokerDockerfileCopiesTheCoreSources(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "..")
	plain := buildStageSources(t, filepath.Join(root, "core", "Dockerfile"))
	broker := buildStageSources(t, filepath.Join(root, "core", "Dockerfile.dexbroker"))
	if len(plain) == 0 {
		t.Fatal("core/Dockerfile build stage copies nothing")
	}
	for _, source := range plain {
		if !slices.Contains(broker, source) {
			t.Errorf("core/Dockerfile.dexbroker build stage does not copy %q", source)
		}
	}
}

// buildStageSources lists the build-context sources the first stage copies.
func buildStageSources(t *testing.T, path string) []string {
	t.Helper()
	contents, err := os.ReadFile(path) // #nosec G304 -- fixed repository path.
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	stages := 0
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "FROM":
			stages++
		case "COPY":
			if stages != 1 || len(fields) < 3 || strings.HasPrefix(fields[1], "--from=") {
				continue
			}
			sources = append(sources, fields[1:len(fields)-1]...)
		}
	}
	return sources
}
