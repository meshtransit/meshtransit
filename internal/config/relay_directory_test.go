package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestRelayDirectoryConfigOwnsValidatedReference(t *testing.T) {
	t.Parallel()

	config := relayDirectoryConfigFixture(t)
	path, digest, err := config.Values()
	if err != nil || path != "/etc/meshtransit/relay-directory.json" ||
		digest == [32]byte{} {
		t.Fatalf("Values() = (%q, %x, %v)", path, digest, err)
	}
	for _, formatted := range []string{
		fmt.Sprint(config),
		fmt.Sprintf("%+v", config),
		fmt.Sprintf("%#v", config),
		config.LogValue().String(),
	} {
		if formatted != redactedValue || strings.Contains(formatted, "relay-directory") {
			t.Fatalf("formatting exposed directory reference: %q", formatted)
		}
	}
}

func TestRelayDirectoryConfigRejectsInvalidReference(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		path   string
		digest string
	}{
		{name: "relative path", path: "relay-directory.json", digest: "sha256:" + strings.Repeat("1", 64)},
		{name: "missing prefix", path: "/etc/meshtransit/relay-directory.json", digest: strings.Repeat("1", 64)},
		{name: "uppercase digest", path: "/etc/meshtransit/relay-directory.json", digest: "sha256:" + strings.Repeat("A", 64)},
		{name: "zero digest", path: "/etc/meshtransit/relay-directory.json", digest: "sha256:" + strings.Repeat("0", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRelayDirectoryConfig(test.path, test.digest); err == nil {
				t.Fatal("NewRelayDirectoryConfig() error = nil")
			}
		})
	}
}
