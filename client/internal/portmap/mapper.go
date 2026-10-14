package portmap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/underlay"
)

// Mapper states reported in Status.
const (
	StateIdle        = "idle"        // no port to map yet
	StateSearching   = "searching"   // first attempt in progress
	StateMapped      = "mapped"      // a mapping with a public external address
	StateDoubleNAT   = "double_nat"  // mapped, but the external address is not public
	StateUnavailable = "unavailable" // no gateway, or no protocol answered
	StateFailed      = "failed"      // the gateway answered but the mapping failed
)

// Status is the mapper's current state. External is shown locally on explicit
// request only; it is never logged.
type Status struct {
	State     string
	Protocol  Protocol
	External  netip.AddrPort
	ExpiresAt time.Time // zero for a permanent mapping
	Error     string    // short machine-readable code for unavailable and failed
}

// schedule holds the mapper's intervals; tests shorten them.
type schedule struct {
	check       time.Duration // how often a held mapping is verified
	unavailable time.Duration // retry after no protocol answered
	failed      time.Duration // first retry after a failure, doubling
	maxFailed   time.Duration
	minRenew    time.Duration // earliest renewal after a mapping was obtained
	release     time.Duration // timeout for removing a mapping on stop
}

var defaultSchedule = schedule{
	check:       2 * time.Minute,
	unavailable: 5 * time.Minute,
	failed:      30 * time.Second,
	maxFailed:   5 * time.Minute,
	minRenew:    30 * time.Second,
	release:     2 * time.Second,
}

// attemptTimeout bounds one mapping attempt across all protocols.
const attemptTimeout = 15 * time.Second

// maxRenewalFailures is how many failed renewals in a row a mapping survives
// before it is no longer trusted, even when it has not expired (a permanent
// UPnP lease never does).
const maxRenewalFailures = 3

// Options configures a Mapper. Zero values select the system defaults.
type Options struct {
	Logger     *slog.Logger
	Gateway    func() (Gateway, error)
	Listen     ListenFunc
	HTTPClient *http.Client
	Clock      func() time.Time
}

// Mapper keeps one UDP port mapped on the default gateway.
type Mapper struct {
	logger   *slog.Logger
	gateway  func() (Gateway, error)
	clock    func() time.Time
	clients  []client
	schedule schedule

	wake    chan struct{}
	network chan struct{}
	changes chan struct{}

	mu        sync.Mutex
	port      uint16
	status    Status
	mapping   *Mapping
	preferred Protocol
	failing   int // failed renewals of mapping in a row
}

// New returns a mapper. It does nothing until Run is called and SetPort
// gives it a port.
func New(options Options) *Mapper {
	if options.Gateway == nil {
		options.Gateway = DefaultGateway
	}
	if options.Listen == nil {
		options.Listen = listenUDP
	}
	if options.HTTPClient == nil {
		options.HTTPClient = newUPnPHTTPClient()
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}

	return newMapper(options, []client{
		pcpClient{listen: options.Listen, clock: options.Clock},
		natpmpClient{listen: options.Listen, clock: options.Clock},
		upnpClient{listen: options.Listen, http: options.HTTPClient, clock: options.Clock},
	})
}

func newMapper(options Options, clients []client) *Mapper {
	return &Mapper{
		logger:   options.Logger,
		gateway:  options.Gateway,
		clock:    options.Clock,
		clients:  clients,
		schedule: defaultSchedule,
		wake:     make(chan struct{}, 1),
		network:  make(chan struct{}, 1),
		changes:  make(chan struct{}, 1),
		status:   Status{State: StateIdle},
	}
}

func listenUDP(ctx context.Context, local netip.Addr) (PacketConn, error) {
	conn, err := underlay.ListenConfig().ListenPacket(ctx, "udp4", netip.AddrPortFrom(local, 0).String())
	if err != nil {
		return nil, fmt.Errorf("portmap: listening on udp: %w", err)
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("portmap: not a UDP socket")
	}
	return udp, nil
}

func signal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

// SetPort sets the local UDP port to map; zero removes the mapping.
func (m *Mapper) SetPort(port uint16) {
	m.mu.Lock()
	changed := m.port != port
	m.port = port
	m.mu.Unlock()
	if changed {
		signal(m.wake)
	}
}

// NetworkChanged tells the mapper the host's network changed: the gateway
// and the mapping are checked again now.
func (m *Mapper) NetworkChanged() { signal(m.network) }

// Changes receives a value whenever Candidate's result changes.
func (m *Mapper) Changes() <-chan struct{} { return m.changes }

// Candidate returns the mapped external endpoint when it is public, maps
// the current port, has not expired and its renewals are not failing.
func (m *Mapper) Candidate() (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.candidateLocked()
}

func (m *Mapper) candidateLocked() (netip.AddrPort, bool) {
	mapping := m.mapping
	if mapping == nil || !mapping.PublicExternal() || mapping.Internal != m.port || m.failing > 0 {
		return netip.AddrPort{}, false
	}
	if mapping.Lifetime > 0 && !m.clock().Before(mapping.Obtained.Add(mapping.Lifetime)) {
		return netip.AddrPort{}, false
	}

	return mapping.External, true
}

// Status returns the current state.
func (m *Mapper) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.status
}

// Run maintains the mapping until ctx ends, then removes it.
func (m *Mapper) Run(ctx context.Context) {
	var (
		timer        *time.Timer
		timerC       <-chan time.Time
		networkDirty bool
		failures     int
		lastCheck    time.Time
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		m.release()
	}()
	for {
		next := m.step(ctx, networkDirty, &failures, &lastCheck)
		networkDirty = false
		if timer != nil {
			timer.Stop()
			timer, timerC = nil, nil
		}
		if next > 0 {
			timer = time.NewTimer(next)
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-m.network:
			networkDirty = true
		case <-timerC:
			timer, timerC = nil, nil
		}
	}
}

// step brings the mapping up to date and returns how long to wait before the
// next step; zero waits for a wake-up only.
func (m *Mapper) step(ctx context.Context, networkDirty bool, failures *int, lastCheck *time.Time) time.Duration {
	m.mu.Lock()
	port, current := m.port, m.mapping
	m.mu.Unlock()
	if port == 0 {
		m.drop(ctx, current)
		m.setStatus(Status{State: StateIdle}, nil)

		return 0
	}
	gw, err := m.gateway()
	if err != nil {
		m.drop(ctx, current)
		m.setStatus(Status{State: StateUnavailable, Error: "no_gateway"}, nil)

		return m.schedule.unavailable
	}
	if !gw.translating() {
		// A public local address or gateway means no NAT to open; never send
		// mapping requests to a public router.
		m.drop(ctx, current)
		m.setStatus(Status{State: StateUnavailable, Error: "no_nat"}, nil)

		return m.schedule.unavailable
	}
	if current != nil && (current.Gateway != gw || current.Internal != port) {
		m.drop(ctx, current)
		current = nil
	}
	now := m.clock()
	if current != nil {
		if due := m.renewTime(*current); now.Before(due) {
			if !networkDirty && now.Sub(*lastCheck) < m.schedule.check {
				return minDuration(due.Sub(now), m.schedule.check-now.Sub(*lastCheck))
			}
			*lastCheck = now
			if m.held(ctx, *current) {
				return minDuration(due.Sub(now), m.schedule.check)
			}
			m.logEvent("port mapping lost", current.Protocol)
			current = nil // the gateway lost it: map again now
		}
	}
	if state := m.Status().State; state == StateIdle || state == StateUnavailable {
		m.setStatus(Status{State: StateSearching}, current)
	}
	mapping, err := m.attempt(ctx, gw, port, current)
	if err == nil {
		// Record a mapping even when the session just ended, so release
		// removes it from the gateway.
		*failures = 0
		m.setMapping(mapping)
		if ctx.Err() != nil {
			return 0
		}
		*lastCheck = m.clock()

		return minDuration(m.renewDelay(mapping), m.schedule.check)
	}
	if ctx.Err() != nil {
		return 0
	}
	*lastCheck = m.clock()
	code := errorCode(err)
	m.logFailure(code)
	*failures++
	if current != nil && *failures < maxRenewalFailures {
		// A failed renewal keeps the mapping until it expires, but it is not
		// offered to peers while renewals fail.
		m.mu.Lock()
		m.failing = *failures
		m.mu.Unlock()
		signal(m.changes)
		delay := backoff(m.schedule.failed, m.schedule.maxFailed, *failures)
		if current.Lifetime > 0 {
			if untilExpiry := current.Obtained.Add(current.Lifetime).Sub(m.clock()); untilExpiry > 0 {
				delay = min(delay, untilExpiry)
			}
		}

		return delay
	}
	if current != nil {
		m.drop(ctx, current)
	}
	if errors.Is(err, ErrUnsupported) {
		m.setStatus(Status{State: StateUnavailable, Error: code}, nil)

		return m.schedule.unavailable
	}
	m.setStatus(Status{State: StateFailed, Error: code}, nil)

	return backoff(m.schedule.failed, m.schedule.maxFailed, *failures)
}

// attempt tries each protocol, the one that worked last first. It returns
// the most informative error when all fail: a refusal over no answer.
func (m *Mapper) attempt(ctx context.Context, gw Gateway, port uint16, current *Mapping) (Mapping, error) {
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	order := slices.Clone(m.clients)
	m.mu.Lock()
	preferred := m.preferred
	m.mu.Unlock()
	slices.SortStableFunc(order, func(a, b client) int {
		switch {
		case a.protocol() == preferred && b.protocol() != preferred:
			return -1
		case b.protocol() == preferred && a.protocol() != preferred:
			return 1
		default:
			return 0
		}
	})
	result := ErrUnsupported
	for _, c := range order {
		var previous *Mapping
		if current != nil && current.Protocol == c.protocol() {
			previous = current
		}
		mapping, err := c.mapPort(ctx, gw, port, previous)
		if err == nil {
			if current != nil && current.Protocol != mapping.Protocol {
				m.unmapWith(ctx, *current)
			}

			return mapping, nil
		}
		if ctx.Err() != nil {
			return Mapping{}, ctx.Err()
		}
		if !errors.Is(err, ErrUnsupported) {
			result = err
		}
	}

	return Mapping{}, result
}

func (m *Mapper) held(ctx context.Context, mapping Mapping) bool {
	for _, c := range m.clients {
		if c.protocol() != mapping.Protocol {
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
		defer cancel()
		held, err := c.check(ctx, mapping)

		return held || err != nil // an unanswered check is not proof of loss
	}

	return false
}

// renewTime is when mapping is renewed: half its lifetime, but not before
// minRenew has passed unless the lifetime is shorter than that.
func (m *Mapper) renewTime(mapping Mapping) time.Time {
	due := mapping.renewAt()
	floor := m.schedule.minRenew
	if mapping.Lifetime > 0 {
		floor = min(floor, mapping.Lifetime/2)
	}
	if earliest := mapping.Obtained.Add(floor); due.Before(earliest) {
		return earliest
	}

	return due
}

func (m *Mapper) renewDelay(mapping Mapping) time.Duration {
	if delay := m.renewTime(mapping).Sub(m.clock()); delay > 0 {
		return delay
	}

	return m.schedule.minRenew
}

// drop removes mapping from the gateway (best effort) and forgets it.
func (m *Mapper) drop(ctx context.Context, mapping *Mapping) {
	if mapping == nil {
		return
	}
	if ctx.Err() == nil {
		m.unmapWith(ctx, *mapping)
	}
	m.mu.Lock()
	if m.mapping != nil && *m.mapping == *mapping {
		m.mapping = nil
	}
	m.mu.Unlock()
	signal(m.changes)
}

func (m *Mapper) unmapWith(ctx context.Context, mapping Mapping) {
	ctx, cancel := context.WithTimeout(ctx, m.schedule.release)
	defer cancel()
	for _, c := range m.clients {
		if c.protocol() == mapping.Protocol {
			if err := c.unmap(ctx, mapping); err != nil && m.logger != nil {
				m.logger.Debug("port mapping removal failed", "protocol", string(mapping.Protocol),
					"error_code", errorCode(err))
			}

			return
		}
	}
}

// release removes the mapping when the mapper stops.
func (m *Mapper) release() {
	m.mu.Lock()
	mapping := m.mapping
	m.mapping, m.port, m.failing = nil, 0, 0
	m.status = Status{State: StateIdle}
	m.mu.Unlock()
	if mapping != nil {
		m.unmapWith(context.Background(), *mapping)
		signal(m.changes)
	}
}

func (m *Mapper) setMapping(mapping Mapping) {
	state := StateMapped
	if !mapping.PublicExternal() {
		state = StateDoubleNAT
	}
	status := Status{State: state, Protocol: mapping.Protocol, External: mapping.External}
	if mapping.Lifetime > 0 {
		status.ExpiresAt = mapping.Obtained.Add(mapping.Lifetime)
	}
	m.mu.Lock()
	m.preferred = mapping.Protocol
	m.mu.Unlock()
	m.setStatus(status, &mapping)
}

// setStatus records status and mapping, signalling a candidate change.
func (m *Mapper) setStatus(status Status, mapping *Mapping) {
	m.mu.Lock()
	before, hadBefore := m.candidateLocked()
	previousState := m.status.State
	m.status, m.mapping, m.failing = status, mapping, 0
	after, hasAfter := m.candidateLocked()
	m.mu.Unlock()
	if hadBefore != hasAfter || before != after {
		signal(m.changes)
	}
	if previousState != status.State {
		m.logEvent("port mapping "+status.State, status.Protocol)
	}
}

func (m *Mapper) logEvent(message string, protocol Protocol) {
	if m.logger == nil {
		return
	}
	if protocol == "" {
		m.logger.Info(message)

		return
	}
	m.logger.Info(message, "protocol", string(protocol))
}

func (m *Mapper) logFailure(code string) {
	if m.logger != nil {
		// Only the code: errors can carry gateway and external addresses.
		m.logger.Debug("port mapping attempt failed", "error_code", code)
	}
}

func errorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoGateway):
		return "no_gateway"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrRefused):
		return "refused"
	case errors.Is(err, ErrInvalidResponse):
		return "invalid_response"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "network"
	}
}

func backoff(first, maximum time.Duration, failures int) time.Duration {
	delay := first
	for i := 1; i < failures && delay < maximum; i++ {
		delay *= 2
	}

	return min(delay, maximum)
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}

	return min(a, b)
}
