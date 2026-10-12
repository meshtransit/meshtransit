//go:build !windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"meshtransit.net/client/internal/config"
	"meshtransit.net/client/internal/dnsconfig"
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

// networkLogAttrs names where host networking is done, for startup logs.
func networkLogAttrs(cfg config.Config) []any {
	return []any{"socket", cfg.NetAdminSocketPath}
}

// platformDNS serves MeshTransit DNS on meshnetd's dedicated link and
// configures the host resolver (systemd-resolved, macOS configd) through it.
func platformDNS(client *netadmin.Client, _ *slog.Logger) (*dnsconfig.Manager, error) {
	resolver, err := dnsconfig.NewServer(client)
	if err != nil {
		return nil, fmt.Errorf("creating local dns resolver: %w", err)
	}
	hostDNS, err := dnsconfig.NewResolvedHost(client, resolver)
	if err != nil {
		return nil, fmt.Errorf("creating host dns configurator: %w", err)
	}
	manager, err := dnsconfig.NewManager(resolver, hostDNS)
	if err != nil {
		return nil, fmt.Errorf("creating dns manager: %w", err)
	}

	return manager, nil
}
