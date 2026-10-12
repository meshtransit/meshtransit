//go:build !windows

package main

import (
	"errors"
	"os"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/localapi"
)

// localAPIOptions authorizes root, meshd's own user and the configured uids
// by their kernel-verified socket credentials.
func localAPIOptions(cfg config.Config) (localapi.Options, error) {
	daemonUID, err := effectiveUID()
	if err != nil {
		return localapi.Options{}, err
	}

	return localapi.Options{
		AllowedUIDs:      append([]uint32{0, daemonUID}, cfg.AllowedUIDs...),
		AllowSocketPeers: cfg.AllowSocketPeers,
	}, nil
}

func effectiveUID() (uint32, error) {
	uid := os.Geteuid()
	if uid < 0 || uint64(uid) > uint64(^uint32(0)) {
		return 0, errors.New("effective uid is outside uint32")
	}

	return uint32(uid), nil
}
