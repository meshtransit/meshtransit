//go:build windows

package main

import (
	"context"
	"errors"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/winadapter"
)

// tunOpener opens the overlay TUN for the data plane.
type tunOpener interface {
	OpenTUN(context.Context, netadmin.TUNConfig) (netadmin.TUN, error)
}

// platformNetwork opens the Wintun adapter inside the service: a Wintun
// session cannot be handed to another process, so there is no meshnetd.
func platformNetwork(cfg config.Config) (tunOpener, *netadmin.Client, error) {
	if cfg.EnableDNS {
		return nil, nil, errors.New("MeshTransit DNS is not available on Windows yet")
	}
	if !cfg.EnableDataPlane {
		return nil, nil, nil
	}

	return dataplane.NewWindowsTUNOpener(), nil, nil
}

// networkLogAttrs names where host networking is done, for startup logs: the
// service itself configures the Wintun adapter, so there is no socket.
func networkLogAttrs(config.Config) []any {
	return []any{"adapter", winadapter.Name}
}
