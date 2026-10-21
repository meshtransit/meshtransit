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

// Both images ship the same pinned DB-IP country table at the path the
// configuration documents (MESHTRANSIT_GEOIP_COUNTRY_FILE).
func TestCoreImagesShipTheSameCountryTable(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "..")
	var tables []string
	for _, name := range []string{"Dockerfile", "Dockerfile.dexbroker"} {
		contents, err := os.ReadFile(filepath.Join(root, "core", name)) // #nosec G304 -- fixed repository path.
		if err != nil {
			t.Fatal(err)
		}
		text := string(contents)
		start := strings.Index(text, "ADD --checksum=sha256:")
		if start < 0 || !strings.Contains(text, "/usr/share/meshtransit/dbip-country-lite.csv.gz") {
			t.Fatalf("core/%s does not ship the pinned country table", name)
		}
		tables = append(tables, strings.Join(strings.Fields(text[start:start+strings.Index(text[start:], ".csv.gz")]), " "))
	}
	if tables[0] != tables[1] {
		t.Fatalf("the images pin different tables:\n%s\n%s", tables[0], tables[1])
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
