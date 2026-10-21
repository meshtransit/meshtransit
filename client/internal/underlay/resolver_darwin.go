//go:build darwin && !ios

package underlay

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/overlayframe"
)

const (
	// scutilPath lists the host's resolvers; any user may run it.
	scutilPath = "/usr/sbin/scutil"
	// upstreamTTL is how long the resolvers read are reused.
	upstreamTTL = 30 * time.Second
)

// physicalResolver asks the resolvers of the host's networks directly, from
// sockets bound to the physical path: while the host routes the Internet
// into the mesh, the system resolver is MeshTransit's, which cannot answer
// before the mesh is up, and the kill switch drops mDNSResponder's own
// queries.
var physicalResolver = &net.Resolver{PreferGo: true, Dial: dialPhysicalResolver}

var upstreams struct {
	mu      sync.Mutex
	servers []netip.AddrPort
	at      time.Time
	next    int
}

func dialPhysicalResolver(ctx context.Context, network, address string) (net.Conn, error) {
	if server, ok := nextUpstream(ctx); ok {
		address = server.String()
	}
	return (&net.Dialer{Control: Control}).DialContext(ctx, network, address)
}

// nextUpstream returns the host networks' resolvers in turn.
func nextUpstream(ctx context.Context) (netip.AddrPort, bool) {
	upstreams.mu.Lock()
	defer upstreams.mu.Unlock()
	refreshUpstreamsLocked(ctx)
	if len(upstreams.servers) == 0 {
		return netip.AddrPort{}, false
	}
	server := upstreams.servers[upstreams.next%len(upstreams.servers)]
	upstreams.next++
	return server, true
}

// NetworkResolvers returns the resolvers of the host's networks: the ones
// MeshTransit's resolver asks during a captive portal window.
func NetworkResolvers() []netip.AddrPort {
	upstreams.mu.Lock()
	defer upstreams.mu.Unlock()
	refreshUpstreamsLocked(context.Background())
	return append([]netip.AddrPort(nil), upstreams.servers...)
}

// refreshUpstreamsLocked reads the resolvers again once they are old.
func refreshUpstreamsLocked(ctx context.Context) {
	if time.Since(upstreams.at) > upstreamTTL || len(upstreams.servers) == 0 {
		lookup, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(lookup, scutilPath, "--dns").Output()
		if err == nil {
			upstreams.servers, upstreams.at = parseScutilResolvers(output), time.Now()
		}
	}
}

// parseScutilResolvers reads the default and scoped resolvers of "scutil
// --dns" on port 53, other than MeshTransit's, the mesh's and loopback, at
// most maximumUpstreams: the servers of the host's own networks.
func parseScutilResolvers(output []byte) []netip.AddrPort {
	var servers []netip.AddrPort
	var block []netip.Addr
	usable := true
	flush := func() {
		if usable {
			for _, address := range block {
				server := netip.AddrPortFrom(address, upstreamPort)
				if len(servers) < maximumUpstreams && !containsAddrPort(servers, server) {
					servers = append(servers, server)
				}
			}
		}
		block, usable = nil, true
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, found := strings.Cut(line, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(line, "resolver #"), strings.HasPrefix(line, "DNS configuration"):
			flush()
		case !found:
		case key == "domain", key == "options", key == "port" && value != "53":
			usable = false // supplemental, mDNS, or another port: not the network's
		case key == "if_index" && (strings.Contains(value, "(utun") || strings.Contains(value, "(lo")):
			usable = false
		case strings.HasPrefix(key, "nameserver["):
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" {
				continue
			}
			address = address.Unmap()
			if address.IsLoopback() || testNet.Contains(address) ||
				overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) {
				continue
			}
			block = append(block, address)
		}
	}
	flush()
	return servers
}

func containsAddrPort(servers []netip.AddrPort, server netip.AddrPort) bool {
	for _, existing := range servers {
		if existing == server {
			return true
		}
	}
	return false
}

// resolver is the resolver of the client's own dials: the system one, or
// physicalResolver while the host routes the Internet into the mesh.
func resolver() *net.Resolver {
	if ExitBound() {
		return physicalResolver
	}
	return nil
}

// Resolver returns the resolver of the client's own lookups.
func Resolver() *net.Resolver {
	if ExitBound() {
		return physicalResolver
	}
	return net.DefaultResolver
}
