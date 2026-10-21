package dnsconfig

import (
	"bufio"
	"net/netip"
	"os"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/overlayframe"
)

// exitResolvedResolvers is where systemd-resolved lists the resolvers its
// stub asks: an exit node whose resolv.conf names only the stub asks these,
// so a consumer's question never takes the host's per-link routing into a
// LAN or VPN zone.
const exitResolvedResolvers = "/run/systemd/resolve/resolv.conf"

// exitInternalSuffixes are names no public resolver serves: a question for
// one is the exit network's own business and is answered NXDOMAIN without
// asking anyone (exit node design §7.2).
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

// typeDS and typeDNSKEY are what a validating resolver asks of a zone
// besides its SOA.
const (
	typeDS     dnsmessage.Type = 43
	typeDNSKEY dnsmessage.Type = 48
)

// exitLocalRefusal decides a question for the exit network's own names,
// name in lower case without the final dot, before anyone is asked:
//   - under a suffix no public resolver serves: NXDOMAIN, whatever the type;
//   - a single label (a LAN host, or a top-level domain): no data, but for
//     the SOA, NS, DS and DNSKEY a resolver asks of a top-level domain; an
//     NXDOMAIN there would deny every name below it (RFC 8020);
//   - under one of the host's search domains, which may be a public domain
//     too: only addresses (filtered as every answer is) and what DNSSEC
//     validation needs; no data for service, text, mail or name server
//     records, which tell an internal zone's hosts and services.
//
// It returns false when the question goes to the upstreams.
func exitLocalRefusal(name string, kind dnsmessage.Type, domains []string) (dnsmessage.RCode, bool) {
	under := func(suffix string) bool { return name == suffix || strings.HasSuffix(name, "."+suffix) }
	switch {
	case name == "":
		return 0, false // the root
	case slices.ContainsFunc(exitInternalSuffixes, under):
		return dnsmessage.RCodeNameError, true
	case !strings.Contains(name, "."):
		if slices.Contains([]dnsmessage.Type{dnsmessage.TypeSOA, dnsmessage.TypeNS, typeDS, typeDNSKEY}, kind) {
			return 0, false
		}
		return dnsmessage.RCodeSuccess, true
	case slices.ContainsFunc(domains, under):
		if slices.Contains([]dnsmessage.Type{
			dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME, dnsmessage.TypeHTTPS, dnsmessage.TypeSVCB,
			dnsmessage.TypeSOA, typeDS, typeDNSKEY,
		}, kind) {
			return 0, false
		}
		return dnsmessage.RCodeSuccess, true
	}
	return 0, false
}
