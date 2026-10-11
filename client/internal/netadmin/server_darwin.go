package netadmin

import (
	"net/netip"
	"os"
)

// NewServer constructs a privileged helper confined to explicit overlay pools.
// The kernel names macOS tunnels, so InterfaceName and DNS.InterfaceName must
// be empty.
func NewServer(options ServerOptions) (*Server, error) {
	return newServerWithDNS(options, unsupportedTUNCreator{}, nil)
}

// validConfiguredInterfaceName requires an empty name: the kernel picks utunN.
func validConfiguredInterfaceName(name string) bool { return name == "" }

// unsupportedTUNCreator stands in until meshnetd creates utun interfaces.
type unsupportedTUNCreator struct{}

func (unsupportedTUNCreator) Open(string, int, uint32, []netip.Prefix, []netip.Prefix) (*os.File, string, error) {
	return nil, "", ErrUnsupported
}

func (unsupportedTUNCreator) ReplaceRoutes(string, []netip.Prefix, []netip.Prefix) error {
	return ErrUnsupported
}
