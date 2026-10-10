package daemon

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/netcheck"
)

// NAT classification schedule (docs/protocol/nat-classification.md §4).
const (
	natRefreshInterval = 5 * time.Minute
	// natMinInterval spaces runs triggered by network changes, so a burst of
	// changes costs one classification. Socket or server changes and
	// on-demand refreshes are not limited by it.
	natMinInterval = 30 * time.Second
	// natRetryInterval is the delay after a failed classification.
	natRetryInterval = 30 * time.Second
)

// NAT classification states reported in Status.
const (
	NATUnavailable = "unavailable" // the packet engine cannot classify
	NATInactive    = "inactive"    // no connected session
	NATPending     = "pending"     // waiting for the first result
	NATReady       = "ready"
	NATStale       = "stale" // last result older than netcheck.MaxReportAge
	NATFailed      = "failed"
)

// ErrNATInactive means no session is running a classification loop, or the
// loop has no socket and servers yet.
var ErrNATInactive = errors.New("daemon: nat classification is not running")

// NATStatus is the daemon's latest NAT classification. PublicEndpoint is
// shown locally on explicit request only; it is never logged.
type NATStatus struct {
	State           string
	NAT             disco.NATInfo
	Step            uint16
	PublicEndpoint  netip.AddrPort
	ServersAnswered int
	ObservedAt      time.Time
	Error           string // short machine-readable code when State is failed
}

// natClassifyingDataPlane is implemented by the packet engine. Prepare runs
// under dataPlaneMu; the returned classification runs without it.
type natClassifyingDataPlane interface {
	PrepareNATClassification(
		[]netip.AddrPort,
	) (pathdiscovery.Socket, dataplane.NATClassification, error)
}

type natRequest struct {
	socket  pathdiscovery.Socket
	servers []netip.AddrPort
}

type natReply struct {
	status NATStatus
	err    error
}

// natSchedule holds the loop's intervals; tests shorten them.
type natSchedule struct {
	refresh, minInterval, retry time.Duration
}

var defaultNATSchedule = natSchedule{
	refresh:     natRefreshInterval,
	minInterval: natMinInterval,
	retry:       natRetryInterval,
}

// natState holds the latest classification and the hand-off to the running
// classification loop of the current session.
type natState struct {
	mu       sync.Mutex
	status   NATStatus
	socket   pathdiscovery.Socket // the socket status.NAT describes
	loopDone chan struct{}        // closed when the current loop exits; nil without a loop
	manual   chan chan natReply
	schedule natSchedule
	// changes receives a value when a classification succeeds, so the
	// endpoint loop reports it.
	changes chan struct{}
}

func newNATState() *natState {
	return &natState{
		status:   NATStatus{State: NATInactive},
		manual:   make(chan chan natReply),
		schedule: defaultNATSchedule,
		changes:  make(chan struct{}, 1),
	}
}

func (n *natState) get() NATStatus {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.status
}

func (n *natState) set(status NATStatus, socket pathdiscovery.Socket) {
	n.mu.Lock()
	n.status, n.socket = status, socket
	n.mu.Unlock()
}

// natStatus returns the classification for Status.
func (s *Service) natStatus() NATStatus {
	if s == nil || s.nat == nil {
		return NATStatus{State: NATUnavailable}
	}
	if _, supported := s.dataPlane.(natClassifyingDataPlane); !supported {
		return NATStatus{State: NATUnavailable}
	}
	status := s.nat.get()
	if status.State == NATReady && s.clock().Sub(status.ObservedAt) > netcheck.MaxReportAge {
		status.State = NATStale
	}

	return status
}

// RefreshNAT runs a classification now on the active session's socket and
// returns its result. It fails with ErrNATInactive when no session runs one.
func (s *Service) RefreshNAT(ctx context.Context) (NATStatus, error) {
	if s == nil || s.nat == nil {
		return NATStatus{}, ErrNATInactive
	}
	s.nat.mu.Lock()
	loopDone := s.nat.loopDone
	s.nat.mu.Unlock()
	if loopDone == nil {
		return NATStatus{}, ErrNATInactive
	}
	reply := make(chan natReply, 1)
	select {
	case s.nat.manual <- reply:
	case <-loopDone:
		return NATStatus{}, ErrNATInactive
	case <-ctx.Done():
		return NATStatus{}, ctx.Err()
	}
	select {
	case r := <-reply:
		return r.status, r.err
	case <-loopDone:
		return NATStatus{}, ErrNATInactive
	case <-ctx.Done():
		return NATStatus{}, ctx.Err()
	}
}

// startNATClassification runs the classification loop for one endpoint
// refresh session. It returns the request channel, a network-change signal
// and a stop function that cancels the loop and waits for it.
func (s *Service) startNATClassification(
	ctx context.Context,
	discoverer endpointDiscoverer,
) (chan natRequest, chan struct{}, func()) {
	plane, supported := discoverer.(natClassifyingDataPlane)
	if !supported || s.nat == nil {
		return nil, nil, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	requests := make(chan natRequest, 1)
	network := make(chan struct{}, 1)
	done := make(chan struct{})
	s.nat.mu.Lock()
	s.nat.loopDone = done
	s.nat.status, s.nat.socket = NATStatus{State: NATPending}, pathdiscovery.Socket{}
	s.nat.mu.Unlock()
	go func() {
		defer close(done)
		s.runNATClassification(ctx, plane, requests, network)
		s.nat.mu.Lock()
		if s.nat.loopDone == done {
			s.nat.status, s.nat.socket = NATStatus{State: NATInactive}, pathdiscovery.Socket{}
			s.nat.loopDone = nil
		}
		s.nat.mu.Unlock()
	}()

	return requests, network, func() {
		cancel()
		<-done
	}
}

// signalNetworkChange records a network change for the loop. A pending signal
// stays set while the loop is busy, so a change is never lost.
func signalNetworkChange(network chan struct{}) {
	select {
	case network <- struct{}{}:
	default:
	}
}

// runNATClassification classifies when the socket or the server set changes,
// after network changes (at most every minInterval), every refresh interval,
// after a failure (retry interval), and on demand.
func (s *Service) runNATClassification(
	ctx context.Context,
	plane natClassifyingDataPlane,
	requests <-chan natRequest,
	network <-chan struct{},
) {
	schedule := s.nat.schedule
	var (
		current natRequest
		hasNext bool
		lastRun time.Time
		timer   *time.Timer
		timerC  <-chan time.Time
	)
	defer func() { stopRefreshTimer(timer) }()
	after := func(delay time.Duration) {
		stopRefreshTimer(timer)
		timer = time.NewTimer(delay)
		timerC = timer.C
	}
	for {
		var reply chan natReply
		urgent := false // bypasses the network-change spacing
		select {
		case <-ctx.Done():
			return
		case request := <-requests:
			changed := !hasNext || request.socket != current.socket ||
				!slices.Equal(request.servers, current.servers)
			current, hasNext = request, true
			if !changed {
				continue
			}
			urgent = true
		case <-network:
		case <-timerC:
			timer, timerC = nil, nil
			urgent = true
		case reply = <-s.nat.manual:
			urgent = true
		}
		if !hasNext {
			if reply != nil {
				reply <- natReply{err: ErrNATInactive}
			}

			continue
		}
		if !urgent && !lastRun.IsZero() {
			if since := time.Since(lastRun); since < schedule.minInterval {
				after(schedule.minInterval - since)

				continue
			}
		}
		status, ok := s.classifyNAT(ctx, plane, current)
		if ctx.Err() != nil {
			return // the session ended mid-run; the caller resets the state
		}
		lastRun = time.Now()
		if reply != nil {
			reply <- natReply{status: status}
		}
		if ok {
			after(schedule.refresh)
		} else {
			after(schedule.retry)
		}
	}
}

// classifyNAT runs one classification for request and records the outcome.
// A failure keeps an earlier good result for the same socket. It reports
// whether the classification succeeded.
func (s *Service) classifyNAT(
	ctx context.Context,
	plane natClassifyingDataPlane,
	request natRequest,
) (NATStatus, bool) {
	report, err := s.classifyNATOnce(ctx, plane, request)
	if err != nil {
		if ctx.Err() != nil {
			return NATStatus{}, false
		}
		code := natErrorCode(err)
		if s.logger != nil {
			// Only the code: errors can carry server and public addresses.
			s.logger.Debug("nat classification failed", "error_code", code)
		}
		failed := NATStatus{State: NATFailed, Error: code}
		s.nat.mu.Lock()
		if s.nat.status.State != NATReady || s.nat.socket != request.socket {
			s.nat.status, s.nat.socket = failed, request.socket
		}
		s.nat.mu.Unlock()

		return failed, false
	}
	answered := make([]netip.Addr, 0, len(report.Report.Observations))
	for _, observation := range report.Report.Observations {
		if !slices.Contains(answered, observation.Server.Addr()) {
			answered = append(answered, observation.Server.Addr())
		}
	}
	status := NATStatus{
		State:           NATReady,
		NAT:             report.Report.NAT,
		Step:            report.Report.Step,
		PublicEndpoint:  report.Report.Mapped,
		ServersAnswered: len(answered),
		ObservedAt:      report.Report.At,
	}
	s.nat.set(status, report.Socket)
	select {
	case s.nat.changes <- struct{}{}:
	default:
	}

	return status, true
}

// classifyNATOnce prepares under dataPlaneMu, as endpoint discovery does,
// and probes without it so a classification never blocks map updates.
func (s *Service) classifyNATOnce(
	ctx context.Context,
	plane natClassifyingDataPlane,
	request natRequest,
) (pathdiscovery.NATReport, error) {
	if len(request.servers) == 0 {
		return pathdiscovery.NATReport{}, pathdiscovery.ErrNoSTUNServers
	}
	s.dataPlaneMu.Lock()
	socket, classify, err := plane.PrepareNATClassification(request.servers)
	s.dataPlaneMu.Unlock()
	if err != nil {
		return pathdiscovery.NATReport{}, err
	}
	if socket != request.socket {
		return pathdiscovery.NATReport{}, pathdiscovery.ErrSocketChanged
	}
	report, err := classify(ctx)
	if err != nil {
		return pathdiscovery.NATReport{}, err
	}
	if report.Socket != request.socket {
		return pathdiscovery.NATReport{}, pathdiscovery.ErrSocketChanged
	}

	return report, nil
}

func natErrorCode(err error) string {
	// netcheck joins ErrNoResponse with the deadline that ended the wait, so
	// it is checked before context errors.
	switch {
	case errors.Is(err, netcheck.ErrNoResponse):
		return "no_response"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	case errors.Is(err, pathdiscovery.ErrNoSTUNServers):
		return "no_stun_servers"
	case errors.Is(err, pathdiscovery.ErrSocketChanged):
		return "socket_changed"
	case errors.Is(err, pathdiscovery.ErrTransportClosed):
		return "socket_closed"
	default:
		return "error"
	}
}
