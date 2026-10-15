//go:build !windows

package main

import (
	"log/slog"
	"strings"

	"meshtransit.net/client/internal/secretstore"
)

// loadIdentityProtector reads the envelope key from its systemd credential
// mount on Linux or from an owner-only file.
func loadIdentityProtector(path, _ string, _ *slog.Logger) (*secretstore.Protector, error) {
	if strings.HasPrefix(path, "/run/credentials/") {
		return secretstore.LoadSystemdCredential(path)
	}

	return secretstore.Load(path)
}
