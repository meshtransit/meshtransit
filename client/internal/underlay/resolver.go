package underlay

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/overlayframe"
)

const (
	// maximumUpstreams bounds the resolvers read.
	maximumUpstreams = 3
	// bypassFor is how long the client asks the upstreams directly once
	// the system resolver failed it, before it tries that one again.
	bypassFor = time.Minute
)

// upstreamResolvers is where systemd-resolved lists the servers it asks
// itself.
var upstreamResolvers = "/run/systemd/resolve/resolv.conf"

// upstreamPort is the port the upstreams answer on; tests change it.
var upstreamPort uint16 = 53

var (
	upstreamRotation atomic.Uint32
	// bypassUntil is the unix nanosecond until which the system resolver is
	// skipped.
	bypassUntil atomic.Int64
	// exitChosen is whether root's settings name a pool (SetExitChosen).
	exitChosen atomic.Bool
)

// SetExitChosen records whether root's settings name a pool: the helper's
// kill switch then drops the system resolver's own queries outside the
// mesh, so the client asks the upstreams directly from the start.
func SetExitChosen(on bool) { exitChosen.Store(on) }

// IsExitChosen reports what SetExitChosen last recorded.
func IsExitChosen() bool { return exitChosen.Load() }

// upstreamResolver resolves names for the client's own sockets with the
// system resolver, as before, and, when that one times out or fails, or
// while the client is bound off the exit routes, with systemd-resolved's
// upstream servers asked directly from a socket of the client's own. While the host routes through an exit node its
// kill switch drops resolved's own queries outside the mesh, and the client
// must still reach Core to bring the mesh back; on any other host resolved
// answers and keeps its routing domains, DNSSEC and encryption.
var upstreamResolver = &net.Resolver{PreferGo: true, Dial: dialResolver}

// usesUpstreamsNow reports whether names go to the upstreams directly: while
// root's settings name a pool, whose kill switch drops resolved's own
// queries, or for a while after the system resolver failed.
func usesUpstreamsNow() bool {
	return exitChosen.Load() || ExitBound() || time.Now().UnixNano() < bypassUntil.Load()
}

func dialResolver(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Control: Control}
	if usesUpstreamsNow() {
		if servers := readUpstreams(upstreamResolvers); len(servers) != 0 {
			address = servers[int(upstreamRotation.Add(1))%len(servers)].String()
			return dialer.DialContext(ctx, network, address)
		}
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil || !strings.HasPrefix(network, "udp") {
		return conn, err
	}
	return &watchedConn{Conn: conn}, nil
}

// watchedConn notes a system resolver that times out or answers SERVFAIL,
// so the next attempt asks the upstreams directly.
type watchedConn struct{ net.Conn }

func (conn *watchedConn) Read(buffer []byte) (int, error) {
	count, err := conn.Conn.Read(buffer)
	var timeout net.Error
	const rcodeServerFailure = 2
	if (err != nil && errors.As(err, &timeout) && timeout.Timeout()) ||
		(err == nil && count >= 4 && buffer[3]&0x0f == rcodeServerFailure) {
		bypassUntil.Store(time.Now().Add(bypassFor).UnixNano())
	}
	return count, err
}

// readUpstreams returns the nameservers of path, other than any in the
// mesh, which the client cannot reach before the mesh is up.
func readUpstreams(path string) []netip.AddrPort {
	file, err := os.Open(path) //nolint:gosec // G304: a fixed system path
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	var servers []netip.AddrPort
	scanner := bufio.NewScanner(file)
	for scanner.Scan() && len(servers) < maximumUpstreams {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		address, err := netip.ParseAddr(fields[1])
		if err != nil || address.Zone() != "" {
			continue // a link-local server with a zone is left to resolved
		}
		address = address.Unmap()
		if overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) {
			continue
		}
		servers = append(servers, netip.AddrPortFrom(address, upstreamPort))
	}
	return servers
}
