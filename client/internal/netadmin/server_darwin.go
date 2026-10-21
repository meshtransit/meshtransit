package netadmin

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dnsLinkPollInterval is how often meshnetd checks that meshd still holds the
// DNS link. When meshd exits, even without cleaning up, the kernel destroys the
// link, and meshnetd then removes the host DNS entry that points at it.
const dnsLinkPollInterval = 2 * time.Second

// NewServer constructs a privileged helper confined to explicit overlay pools.
// The kernel names macOS tunnels, so InterfaceName and DNS.InterfaceName must
// be empty.
func NewServer(options ServerOptions) (*Server, error) {
	var configurator *scutilConfigurator
	if options.DNS != nil {
		path := options.DNS.ScutilPath
		if path == "" {
			path = DefaultScutilPath
		}
		var err error
		if configurator, err = newScutilConfigurator(path); err != nil {
			return nil, err
		}
	}
	if configurator == nil {
		server, err := newServerWithDNS(options, kernelTUNCreator{logger: options.Logger}, nil)
		if err != nil {
			return nil, err
		}
		return server, server.prepareRouted()
	}
	server, err := newServerWithDNS(options, kernelTUNCreator{logger: options.Logger}, configurator)
	if err != nil {
		return nil, err
	}
	if err := server.prepareRouted(); err != nil {
		return nil, err
	}
	server.dnsLoopback = kernelLoopback{}
	// A previous helper may have stopped with its entries and the resolver
	// alias still in place.
	ctx, cancel := context.WithTimeout(context.Background(), helperOperationTimeout)
	defer cancel()
	if err := configurator.Reset(ctx, DNSEndpoint{}); err != nil {
		server.logger.Debug("no stale MeshTransit DNS entry removed", "error", err)
	}
	if err := server.dnsLoopback.Remove(server.dnsEndpoint.Resolver.Addr()); err != nil {
		server.logger.Warn("removing a stale resolver address failed", "error", err)
	}
	server.background = withBackground(server.background, server.watchDNSLink)
	return server, nil
}

// prepareRouted sets up subnet routes when they are enabled, starting from
// none: a previous run may have left routes and pins.
func (s *Server) prepareRouted() error {
	if s.routed == nil {
		return nil
	}
	s.routedConfigurer = kernelRoutedConfigurer{}
	s.hostRouting = kernelHostRouting{}
	s.background = withBackground(s.background, s.watchRouteSettings)
	if err := s.routedConfigurer.Clear(*s.routed, s.allowedUID); err != nil {
		return fmt.Errorf("netadmin: clearing subnet routes left by a previous run: %w", err)
	}
	if s.routed.Exits {
		exitRoutes := newDarwinExitRouteConfigurer(s.allowedUID, s.routed.StatePath)
		if s.routed.CaptiveWindowPath != "" {
			exitRoutes.withCaptive(DarwinCaptiveStatePath(s.routed.StatePath))
		}
		exitRoutes.warn = s.logger.Warn
		s.exitRouteConfigurer = exitRoutes
		// A kill switch a previous run left stays while root's settings
		// name a pool, and is installed if missing; otherwise it goes.
		// A failure is no reason to stop the helper: subnet routes and
		// DNS still work, and the next change of settings tries again.
		if err := s.startExitRoute(); err != nil {
			s.logger.Warn("clearing an exit route left by a previous run failed", "error", err)
		}
		if s.routed.CaptiveWindowPath != "" {
			s.background = withBackground(s.background, s.watchCaptiveWindow)
		}
	}
	return nil
}

// validConfiguredInterfaceName requires an empty name: the kernel picks utunN.
func validConfiguredInterfaceName(name string) bool { return name == "" }

// watchDNSLink removes the host DNS entry once the DNS link it points at is
// gone, so a crashed meshd never leaves names resolving to a dead resolver.
func (s *Server) watchDNSLink(ctx context.Context) {
	ticker := time.NewTicker(dnsLinkPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.resetDNSIfLinkGone(ctx, linkExists)
		}
	}
}

func linkExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func (s *Server) resetDNSIfLinkGone(ctx context.Context, exists func(string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := s.dnsEndpoint.InterfaceName
	if s.dns == nil || name == "" || exists(name) {
		return
	}
	operationCtx, cancel := context.WithTimeout(ctx, helperOperationTimeout)
	defer cancel()
	if err := s.dns.Reset(operationCtx, s.dnsEndpoint); err != nil {
		s.logger.Warn("removing MeshTransit DNS after its link went away failed", "error", err)
		return
	}
	if s.dnsLoopback != nil {
		if err := s.dnsLoopback.Remove(s.dnsEndpoint.Resolver.Addr()); err != nil {
			s.logger.Warn("removing the resolver address failed", "error", err)
		}
	}
	s.logger.Info("MeshTransit DNS removed: its link went away", "interface", name)
	s.dnsEndpoint.InterfaceName = ""
}
