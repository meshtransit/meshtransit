package dnsconfig

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/shared/internet"
)

const (
	// exitQuestionsPerSecond and exitQuestionBurst bound one consumer's
	// questions (exit node design §7.2).
	exitQuestionsPerSecond = 64
	exitQuestionBurst      = 64
	// maxExitConsumersTracked bounds the consumers whose rate is kept.
	maxExitConsumersTracked = 4096
	// maxExitConsumerQuestions and maxExitConsumerConnections bound what
	// one consumer holds of the forwarder at once.
	maxExitConsumerQuestions   = 32
	maxExitConsumerConnections = 8
	// exitFailingAfter is how long the upstreams must have answered
	// nothing before the forwarder reports failing: one consumer's names
	// that never resolve do not make it fail.
	exitFailingAfter = 30 * time.Second
	// maxExitUpstreams bounds the resolvers asked, in order.
	maxExitUpstreams = 4
	// exitUpstreamRefresh is how often the host's resolvers and addresses
	// are read again.
	exitUpstreamRefresh = 30 * time.Second
	// exitFailuresToFail is how many questions in a row the upstreams fail
	// before the forwarder reports failing.
	exitFailuresToFail = 3
)

// exitSystemResolvers is where an exit node without upstreams of its pool
// finds the host's resolvers.
const exitSystemResolvers = "/etc/resolv.conf"

// ExitForwarder answers the DNS questions of an exit node's consumers on its
// overlay addresses (exit node design §7.2): the helper redirects port 53
// to netadmin.ExitDNSPort, and the packet filter admits only consumers the
// pool's rules name. It asks the pool's upstreams, or the host's own
// resolvers, from the host's network, and never tells a consumer an address
// that is no Internet for it. It logs no names.
type ExitForwarder struct {
	logger *slog.Logger
	// local returns the host's own addresses and attached subnets.
	local func() []netip.Prefix
	// port, upstreamPort, resolvConf and resolvedConf are fixed but for
	// tests.
	port         uint16
	upstreamPort uint16
	resolvConf   string
	resolvedConf string

	// lifecycle serializes Configure and owns the listeners.
	lifecycle sync.Mutex
	udp       []*net.UDPConn
	tcp       []*net.TCPListener
	cancel    context.CancelFunc
	wait      sync.WaitGroup
	slots     chan struct{}
	tcpSlots  chan struct{}

	// mu guards what the questions read.
	mu         sync.Mutex
	addresses  []netip.Addr
	running    bool
	configured []netip.AddrPort
	system     []netip.AddrPort
	domains    []string
	private    []netip.Prefix
	readAt     time.Time
	buckets    map[netip.Addr]*exitBucket
	failures   int
	// answeredAt is the upstreams' last answer, or when the forwarder
	// started; startFailed means it could not listen.
	answeredAt  time.Time
	startFailed bool
	// held counts each consumer's questions and connections in flight.
	held map[netip.Addr]int
}

type exitBucket struct {
	tokens float64
	at     time.Time
}

// NewExitForwarder returns a stopped forwarder; local, when nil, reads the
// host's interface addresses.
func NewExitForwarder(logger *slog.Logger, local func() []netip.Prefix) *ExitForwarder {
	if local == nil {
		local = interfacePrefixes
	}
	return &ExitForwarder{
		logger: logger, local: local, buckets: map[netip.Addr]*exitBucket{}, held: map[netip.Addr]int{},
		port: netadmin.ExitDNSPort, upstreamPort: 53, resolvConf: exitSystemResolvers,
		resolvedConf: exitResolvedResolvers,
		slots: make(chan struct{}, maxConcurrentQueries), tcpSlots: make(chan struct{}, maxTCPConnections),
	}
}

// Configure listens on addresses, the exit node's overlay addresses, and
// asks upstreams (the pool's, Internet addresses) or, without any, the
// host's resolvers. No addresses stops it.
func (f *ExitForwarder) Configure(addresses, upstreams []netip.Addr) {
	if f == nil {
		return
	}
	addresses = slices.Clone(addresses)
	slices.SortFunc(addresses, netip.Addr.Compare)
	configured := make([]netip.AddrPort, 0, len(upstreams))
	for _, upstream := range upstreams {
		if internet.Contains(upstream) && len(configured) < maxExitUpstreams {
			configured = append(configured, netip.AddrPortFrom(upstream, f.upstreamPort))
		}
	}
	f.lifecycle.Lock()
	defer f.lifecycle.Unlock()
	f.mu.Lock()
	f.configured = configured
	unchanged := slices.Equal(addresses, f.addresses) && (len(addresses) == 0 || f.running)
	f.mu.Unlock()
	if unchanged {
		return
	}
	f.stopLocked()
	if len(addresses) == 0 {
		return
	}
	f.mu.Lock()
	f.addresses, f.running, f.readAt, f.answeredAt = addresses, true, time.Time{}, time.Now()
	f.mu.Unlock()
	if err := f.startLocked(addresses); err != nil {
		if f.logger != nil {
			f.logger.Warn("the exit node's DNS forwarder could not listen; retrying with the next map", "error", err)
		}
		f.stopLocked()
		f.mu.Lock()
		f.startFailed = true
		f.mu.Unlock()
	}
}

// Failing reports whether the forwarder could not listen, has no upstream
// to ask, or its upstreams failed the last questions in a row and answered
// none for exitFailingAfter.
func (f *ExitForwarder) Failing() bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshLocked(time.Now())
	return f.startFailed || (f.running && len(f.configured) == 0 && len(f.system) == 0) ||
		(f.running && f.failures >= exitFailuresToFail && time.Since(f.answeredAt) >= exitFailingAfter)
}

// Close stops the forwarder.
func (f *ExitForwarder) Close() {
	f.Configure(nil, nil)
}

func (f *ExitForwarder) startLocked(addresses []netip.Addr) error {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	for _, address := range addresses {
		endpoint := netip.AddrPortFrom(address, f.port)
		udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(endpoint))
		if err != nil {
			return err
		}
		f.udp = append(f.udp, udp)
		tcp, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(endpoint))
		if err != nil {
			return err
		}
		f.tcp = append(f.tcp, tcp)
		f.wait.Add(2)
		go f.serveUDP(ctx, udp)
		go f.serveTCP(ctx, tcp)
	}
	return nil
}

// stopLocked closes the listeners and waits for the questions in flight;
// the caller holds lifecycle only.
func (f *ExitForwarder) stopLocked() {
	if f.cancel != nil {
		f.cancel()
	}
	for _, udp := range f.udp {
		_ = udp.Close()
	}
	for _, tcp := range f.tcp {
		_ = tcp.Close()
	}
	f.wait.Wait()
	f.udp, f.tcp, f.cancel = nil, nil, nil
	f.mu.Lock()
	f.addresses, f.running, f.failures, f.startFailed = nil, false, 0, false
	clear(f.held)
	f.mu.Unlock()
}

func (f *ExitForwarder) serveUDP(ctx context.Context, listener *net.UDPConn) {
	defer f.wait.Done()
	buffer := make([]byte, maxQueryBytes+1)
	for {
		count, remote, err := listener.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		query := append([]byte(nil), buffer[:count]...)
		consumer := remote.Addr().Unmap()
		if !f.hold(consumer, maxExitConsumerQuestions) {
			_, _ = listener.WriteToUDPAddrPort(busyResponse(query), remote)
			continue
		}
		select {
		case f.slots <- struct{}{}:
			f.wait.Add(1)
			go func() {
				defer f.wait.Done()
				defer func() { <-f.slots }()
				defer f.release(consumer)
				if response := f.answer(ctx, query, "udp", remote.Addr()); len(response) != 0 {
					_, _ = listener.WriteToUDPAddrPort(response, remote)
				}
			}()
		default:
			f.release(consumer)
			_, _ = listener.WriteToUDPAddrPort(busyResponse(query), remote)
		}
	}
}

// hold counts one more question or connection of consumer, refusing it at
// limit.
func (f *ExitForwarder) hold(consumer netip.Addr, limit int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held[consumer] >= limit {
		return false
	}
	f.held[consumer]++
	return true
}

func (f *ExitForwarder) release(consumer netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held[consumer]--; f.held[consumer] <= 0 {
		delete(f.held, consumer)
	}
}

func (f *ExitForwarder) serveTCP(ctx context.Context, listener *net.TCPListener) {
	defer f.wait.Done()
	for {
		connection, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		remote, _ := netip.ParseAddrPort(connection.RemoteAddr().String())
		consumer := remote.Addr().Unmap()
		if !f.hold(consumer, maxExitConsumerConnections) {
			_ = connection.Close()
			continue
		}
		select {
		case f.tcpSlots <- struct{}{}:
			f.wait.Add(1)
			go func() {
				defer f.wait.Done()
				defer func() { <-f.tcpSlots }()
				defer f.release(consumer)
				f.serveConnection(ctx, connection)
			}()
		default:
			f.release(consumer)
			_ = connection.Close()
		}
	}
}

func (f *ExitForwarder) serveConnection(ctx context.Context, connection *net.TCPConn) {
	defer func() { _ = connection.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	remote, _ := netip.ParseAddrPort(connection.RemoteAddr().String())
	reader := bufio.NewReader(connection)
	for {
		if err := connection.SetDeadline(time.Now().Add(tcpIdleTimeout)); err != nil {
			return
		}
		var length uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil || length < 12 || length > maxQueryBytes {
			return
		}
		query := make([]byte, int(length))
		if _, err := io.ReadFull(reader, query); err != nil {
			return
		}
		response := f.answer(ctx, query, "tcp", remote.Addr())
		if len(response) == 0 || len(response) > maxDNSMessageBytes {
			return
		}
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(response))) //nolint:gosec // G115: bounded above
		if _, err := connection.Write(append(framed, response...)); err != nil {
			return
		}
	}
}

// answer forwards one consumer's question and filters the answer.
func (f *ExitForwarder) answer(ctx context.Context, query []byte, transport string, consumer netip.Addr) []byte {
	message, question, _, err := parseQuery(query)
	if err != nil {
		if errors.Is(err, errUnsupportedEDNSVersion) {
			response, _ := unsupportedEDNSVersionResponse(message)
			return response
		}
		return formatError(query)
	}
	upstreams, private, domains, admitted := f.prepare(consumer, time.Now())
	if name := strings.TrimSuffix(strings.ToLower(question.Name.String()), "."); question.Type != dnsmessage.TypePTR &&
		exitLocalName(name, domains) {
		// The exit network's own names stay its own: asking its resolver
		// for them would tell a consumer its hosts and services.
		response, _ := negativeResponse(message, question, dnsmessage.RCodeNameError, ".", Plan{})
		return response
	}
	if question.Type == dnsmessage.TypePTR {
		// The exit network's own names stay its own.
		if address, reverse := parseReverseName(strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")); reverse &&
			(!internet.Contains(address) || slices.ContainsFunc(private, func(prefix netip.Prefix) bool {
				return prefix.Contains(address)
			})) {
			response, _ := negativeResponse(message, question, dnsmessage.RCodeNameError, ".", Plan{})
			return response
		}
	}
	if !admitted || len(upstreams) == 0 {
		response, _ := failureResponse(query, message, question, Plan{}, transport, errForwardBusy)
		return response
	}
	forwardCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	response, err := forwardQuery(forwardCtx, query, question, upstreams, transport)
	f.noteUpstream(err == nil)
	if err == nil {
		response, err = withoutPrivateAnswers(response, func(address netip.Addr) bool {
			return !internet.Contains(address) || slices.ContainsFunc(private, func(prefix netip.Prefix) bool {
				return prefix.Contains(address)
			})
		})
	}
	if err != nil {
		failed, _ := failureResponse(query, message, question, Plan{}, transport, err)
		return failed
	}
	limited, err := limitUDPResponse(query, response, transport)
	if err != nil {
		return nil
	}
	return limited
}

// prepare charges consumer one question and returns the upstreams, the
// host's own networks and its search domains, read again when stale.
func (f *ExitForwarder) prepare(consumer netip.Addr, now time.Time) ([]netip.AddrPort, []netip.Prefix, []string,
	bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshLocked(now)
	upstreams := f.configured
	if len(upstreams) == 0 {
		upstreams = f.system
	}
	return slices.Clone(upstreams), slices.Clone(f.private), slices.Clone(f.domains), f.chargeLocked(consumer, now)
}

// refreshLocked reads the host's resolvers, search domains and networks
// again when stale.
func (f *ExitForwarder) refreshLocked(now time.Time) {
	if now.Sub(f.readAt) < exitUpstreamRefresh {
		return
	}
	f.readAt = now
	f.private = f.local()
	f.system, f.domains = hostResolvers(f.resolvConf, f.resolvedConf, f.upstreamPort)
}

func (f *ExitForwarder) chargeLocked(consumer netip.Addr, now time.Time) bool {
	bucket := f.buckets[consumer]
	if bucket == nil {
		if len(f.buckets) >= maxExitConsumersTracked {
			for address, other := range f.buckets {
				if now.Sub(other.at) > time.Second {
					delete(f.buckets, address)
				}
			}
			if len(f.buckets) >= maxExitConsumersTracked {
				return false
			}
		}
		bucket = &exitBucket{tokens: exitQuestionBurst, at: now}
		f.buckets[consumer] = bucket
	}
	bucket.tokens = min(exitQuestionBurst, bucket.tokens+now.Sub(bucket.at).Seconds()*exitQuestionsPerSecond)
	bucket.at = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (f *ExitForwarder) noteUpstream(answered bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if answered {
		f.failures, f.answeredAt = 0, time.Now()
		return
	}
	f.failures++
}

// interfacePrefixes returns every address of the host's interfaces as a
// host prefix and as its attached subnet.
func interfacePrefixes() []netip.Prefix {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, 2*len(addresses))
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(network.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		bits, _ := network.Mask.Size()
		if subnet, err := ip.Prefix(bits); err == nil {
			prefixes = append(prefixes, subnet)
		}
		prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return prefixes
}
