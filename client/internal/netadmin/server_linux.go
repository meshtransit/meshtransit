package netadmin

import "fmt"

// NewServer constructs a privileged helper confined to explicit overlay pools.
func NewServer(options ServerOptions) (*Server, error) {
	var configurator dnsConfigurator
	if options.DNS != nil {
		resolved, err := newResolvectlConfigurator(options.DNS.ResolvectlPath)
		if err != nil {
			return nil, err
		}
		configurator = resolved
	}

	server, err := newServerWithDNS(options, kernelTUNCreator{}, configurator)
	if err != nil {
		return nil, err
	}
	if options.Routed != nil {
		server.routedConfigurer = kernelRoutedConfigurer{}
		server.hostRouting = kernelHostRouting{}
		server.background = server.watchRouteSettings
		// A previous run may have left routes and its rule: start clean.
		if err := server.routedConfigurer.Clear(*server.routed, server.allowedUID); err != nil {
			return nil, fmt.Errorf("netadmin: clearing subnet routes left by a previous run: %w", err)
		}
		if options.Routed.NftTable != "" {
			server.servedConfigurer = newKernelServedConfigurer(*options.Routed)
			// Nor forwarding, also after a crash: the state file restores
			// the host settings it changed. A host that cannot forward
			// still serves as a consumer, so a failure here is not fatal.
			if err := server.servedConfigurer.Clear(); err != nil {
				server.logger.Warn("clearing subnet forwarding left by a previous run failed", "error", err)
			}
		}
		if options.Routed.ExitTable != 0 {
			server.exitRouteConfigurer = newKernelExitRouteConfigurer(*options.Routed, options.AllowedUID)
			// A kill switch a previous run left stays while root's settings
			// name a pool, and is installed if missing; otherwise it goes.
			if err := server.startExitRoute(); err != nil {
				return nil, fmt.Errorf("netadmin: clearing the exit route left by a previous run: %w", err)
			}
		}
	}
	return server, nil
}

// validConfiguredInterfaceName requires the fixed mesh* names root chose.
func validConfiguredInterfaceName(name string) bool {
	return validInterfaceName(name) && name[:4] == "mesh"
}
