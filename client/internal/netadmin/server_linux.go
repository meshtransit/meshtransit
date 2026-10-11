package netadmin

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

	return newServerWithDNS(options, kernelTUNCreator{}, configurator)
}

// validConfiguredInterfaceName requires the fixed mesh* names root chose.
func validConfiguredInterfaceName(name string) bool {
	return validInterfaceName(name) && name[:4] == "mesh"
}
