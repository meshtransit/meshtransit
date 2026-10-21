package dnsconfig

import (
	"bufio"
	"net/netip"
	"os"
	"slices"
	"strings"

	"meshtransit.net/client/internal/overlayframe"
)

// exitResolvedResolvers is where systemd-resolved lists the resolvers its
// stub asks: an exit node whose resolv.conf names only the stub asks these,
// so a consumer's question never takes the host's per-link routing into a
// LAN or VPN zone.
const exitResolvedResolvers = "/run/systemd/resolve/resolv.conf"

// exitInternalSuffixes are names no public resolver serves: a question for
// one, or for a single label, is the exit network's own business and is
// answered NXDOMAIN without asking anyone (exit node design §7.2).
var exitInternalSuffixes = []string{
	"local", "localhost", "localdomain", "internal", "intranet", "lan", "home", "corp", "private",
	"home.arpa", "invalid",
}

// hostResolvers returns the host's resolvers and search domains from
// resolvConf, and, when it names only a loopback stub, the resolvers behind
// it from resolvedConf; at most maxExitUpstreams resolvers, none in the mesh.
func hostResolvers(resolvConf, resolvedConf string, port uint16) ([]netip.AddrPort, []string) {
	servers, domains := readResolvConf(resolvConf, port)
	if len(servers) == 0 || slices.ContainsFunc(servers, func(server netip.AddrPort) bool {
		return !server.Addr().IsLoopback()
	}) {
		return servers, domains
	}
	behind, more := readResolvConf(resolvedConf, port)
	behind = slices.DeleteFunc(behind, func(server netip.AddrPort) bool { return server.Addr().IsLoopback() })
	if len(behind) == 0 {
		return servers, domains // a stub of another kind, such as dnsmasq
	}
	for _, domain := range more {
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return behind, domains
}

// readResolvConf returns the nameservers and search domains of path.
func readResolvConf(path string, port uint16) ([]netip.AddrPort, []string) {
	file, err := os.Open(path) //nolint:gosec // G304: a fixed system path
	if err != nil {
		return nil, nil
	}
	defer func() { _ = file.Close() }()
	var servers []netip.AddrPort
	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			address, err := netip.ParseAddr(fields[1])
			address = address.Unmap()
			if err != nil || address.Zone() != "" || len(servers) >= maxExitUpstreams ||
				overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) {
				continue
			}
			servers = append(servers, netip.AddrPortFrom(address, port))
		case "search", "domain":
			for _, domain := range fields[1:] {
				domain = strings.Trim(strings.ToLower(domain), ".")
				if domain != "" && len(domains) < 64 && !slices.Contains(domains, domain) {
					domains = append(domains, domain)
				}
			}
		}
	}
	return servers, domains
}

// exitLocalName reports whether name (lower case, without the final dot) is
// a single label, under one of the host's search domains, or under a suffix
// no public resolver serves.
func exitLocalName(name string, domains []string) bool {
	if name == "" || !strings.Contains(name, ".") {
		return name != "" // the root is asked; a single label is local
	}
	under := func(suffix string) bool { return name == suffix || strings.HasSuffix(name, "."+suffix) }
	return slices.ContainsFunc(exitInternalSuffixes, under) || slices.ContainsFunc(domains, under)
}
