package captive

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// networkdLinks is where systemd-networkd records each link's state, the
// captive portal API URI its DHCP or router advertisement gave among it.
const networkdLinks = "/run/systemd/netif/links"

// APIURIs returns the captive portal API URIs the host's networks gave.
func APIURIs() []string { return apiURIsIn(networkdLinks) }

func apiURIsIn(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var uris []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		file, err := os.Open(filepath.Join(dir, entry.Name())) //nolint:gosec // G304: networkd's own state directory
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			uri, found := strings.CutPrefix(scanner.Text(), "CAPTIVE_PORTAL=")
			if found && strings.HasPrefix(uri, "https://") && !slices.Contains(uris, uri) && len(uris) < 4 {
				uris = append(uris, uri)
			}
		}
		_ = file.Close()
	}
	return uris
}
