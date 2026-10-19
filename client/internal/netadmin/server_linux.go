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
		server.background = server.watchRouteSettings
		// A previous run may have left routes and its rule: start clean.
		if err := server.routedConfigurer.Clear(*server.routed, server.allowedUID); err != nil {
			return nil, fmt.Errorf("netadmin: clearing subnet routes left by a previous run: %w", err)
		}
	}
	return server, nil
}

// validConfiguredInterfaceName requires the fixed mesh* names root chose.
func validConfiguredInterfaceName(name string) bool {
	return validInterfaceName(name) && name[:4] == "mesh"
}
