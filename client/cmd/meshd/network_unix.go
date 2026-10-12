//go:build !windows

package main

import (
	"context"
	"time"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/netadmin"
)

// tunOpener opens the overlay TUN for the data plane.
type tunOpener interface {
	OpenTUN(context.Context, netadmin.TUNConfig) (netadmin.TUN, error)
}

// platformNetwork returns meshnetd's client, which opens the TUN and
// configures DNS; meshd itself holds no network privileges.
func platformNetwork(cfg config.Config) (tunOpener, *netadmin.Client, error) {
	if !cfg.EnableDataPlane && !cfg.EnableDNS {
		return nil, nil, nil
	}
	client, err := netadmin.NewClient(cfg.NetAdminSocketPath, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}

	return client, client, nil
}
