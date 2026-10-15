//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/winadapter"
	"meshtransit.net/client/internal/windns"
)

// tunOpener opens the overlay TUN for the data plane.
type tunOpener interface {
	OpenTUN(context.Context, netadmin.TUNConfig) (netadmin.TUN, error)
}

// platformNetwork opens the Wintun adapter inside the service: a Wintun
// session cannot be handed to another process, so there is no meshnetd.
func platformNetwork(cfg config.Config) (tunOpener, *netadmin.Client, error) {
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

// platformDNS serves MeshTransit DNS on its loopback address and sends the
// Network's DNS domains to it through an NRPT rule.
func platformDNS(_ *netadmin.Client, logger *slog.Logger) (*dnsconfig.Manager, error) {
	resolver, err := dnsconfig.NewServer(windns.Opener{})
	if err != nil {
		return nil, fmt.Errorf("creating local dns resolver: %w", err)
	}
	hostDNS, err := windns.NewNRPTHost(resolver, logger.With("component", "dns"))
	if err != nil {
		return nil, err
	}
	manager, err := dnsconfig.NewManager(resolver, hostDNS)
	if err != nil {
		return nil, fmt.Errorf("creating dns manager: %w", err)
	}
	manager.SetLogger(logger)

	return manager, nil
}
