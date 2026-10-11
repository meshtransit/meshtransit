package netadmin

// NewServer constructs a privileged helper confined to explicit overlay pools.
// The kernel names macOS tunnels, so InterfaceName and DNS.InterfaceName must
// be empty.
func NewServer(options ServerOptions) (*Server, error) {
	if options.DNS != nil {
		return nil, ErrUnsupported // host DNS on macOS comes with C1i
	}
	return newServerWithDNS(options, kernelTUNCreator{}, nil)
}

// validConfiguredInterfaceName requires an empty name: the kernel picks utunN.
func validConfiguredInterfaceName(name string) bool { return name == "" }
