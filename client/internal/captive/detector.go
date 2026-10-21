package captive

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Timing of the checks (exit node design §17.3).
const (
	// downBefore is how long the control session must be down, while the
	// host uses an exit node, before the network is checked.
	downBefore = 10 * time.Second
	// heldEvery is the spacing while a portal is suspected or found.
	heldEvery = 15 * time.Second
	// tick is how often the conditions are looked at.
	tick = time.Second
)

// backoff spaces the checks while nothing is found.
var backoff = []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}

// Inputs are what the detector needs of the client, read every tick.
type Inputs struct {
	// ExitWanted: the host's settings name a pool.
	ExitWanted bool
	// ControlUp: the control session is synchronized.
	ControlUp bool
	// Relays are the relay addresses the last map gave (or that were kept
	// from it), and RelayName one relay's host name.
	Relays    []netip.Addr
	RelayName string
}

// State is what the detector knows, for status.
type State struct {
	Verdict Verdict
	// URL is the sign-in page the network named, if any.
	URL string
	// Since is when the verdict was first reached, CheckedAt the last check.
	Since     time.Time
	CheckedAt time.Time
}

// Checker is what a check uses; Prober implements the probes.
type Checker interface {
	Probe(ctx context.Context, address netip.Addr) Result
	FetchAPI(ctx context.Context, uri string) (Result, error)
}

// Detector checks the network while the host uses an exit node and its
// control session is down.
type Detector struct {
	inputs   func() Inputs
	checker  Checker
	apiURIs  func() []string
	resolve  func(ctx context.Context, name string) ([]netip.Addr, error)
	clock    func() time.Time
	onChange func(State)

	mu        sync.Mutex
	state     State
	downSince time.Time
	nextAt    time.Time
	attempt   int
}

// Config wires a Detector.
type Config struct {
	Inputs  func() Inputs
	Checker Checker
	// APIURIs returns the networks' captive portal API URIs (APIURIs).
	APIURIs func() []string
	// Resolve asks the network's resolver, from the client's own socket.
	Resolve func(ctx context.Context, name string) ([]netip.Addr, error)
	Clock   func() time.Time
	// OnChange is told every new verdict or sign-in page.
	OnChange func(State)
}

// NewDetector returns a detector with no verdict.
func NewDetector(config Config) *Detector {
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.APIURIs == nil {
		config.APIURIs = func() []string { return nil }
	}
	return &Detector{
		inputs: config.Inputs, checker: config.Checker, apiURIs: config.APIURIs, resolve: config.Resolve,
		clock: config.Clock, onChange: config.OnChange, state: State{Verdict: VerdictNone},
	}
}

// State returns what the detector knows.
func (d *Detector) State() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

// NetworkChanged checks again at once: another Wi-Fi, another portal.
func (d *Detector) NetworkChanged() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nextAt, d.attempt = time.Time{}, 0
}

// Run checks until ctx ends.
func (d *Detector) Run(ctx context.Context) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		d.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Step looks at the conditions once and checks the network when due.
func (d *Detector) Step(ctx context.Context) {
	in := d.inputs()
	now := d.clock()
	d.mu.Lock()
	if !in.ExitWanted || in.ControlUp {
		// Nothing to find: the tunnel works, or no exit is used.
		d.downSince, d.nextAt, d.attempt = time.Time{}, time.Time{}, 0
		d.mu.Unlock()
		d.record(Result{Verdict: VerdictNone}, now)
		return
	}
	if d.downSince.IsZero() {
		d.downSince = now
	}
	due := now.Sub(d.downSince) >= downBefore && !now.Before(d.nextAt)
	d.mu.Unlock()
	if !due {
		return
	}
	result := d.check(ctx, in)
	now = d.clock()
	d.mu.Lock()
	wait := heldEvery
	if result.Verdict == VerdictNone || result.Verdict == VerdictUnknown {
		wait = backoff[min(d.attempt, len(backoff)-1)]
		d.attempt++
	} else {
		d.attempt = 0
	}
	d.nextAt = now.Add(wait)
	d.mu.Unlock()
	d.record(result, now)
}

// check asks, in order of trust: the network's API, the relay probe, then
// the network resolver about the relay's name.
func (d *Detector) check(ctx context.Context, in Inputs) Result {
	for _, uri := range d.apiURIs() {
		if result, err := d.checker.FetchAPI(ctx, uri); err == nil {
			return result
		}
	}
	addresses := relayAddresses(in.Relays)
	resolved, resolveErr := []netip.Addr(nil), error(nil)
	if in.RelayName != "" && d.resolve != nil {
		resolved, resolveErr = d.resolve(ctx, in.RelayName)
	}
	if len(addresses) == 0 {
		// A cold start with no map: the network's answer for the relay's
		// name is probed, a portal's own address included.
		addresses = relayAddresses(resolved)
	}
	verdict := Result{Verdict: VerdictUnknown}
	for _, address := range addresses {
		result := d.checker.Probe(ctx, address)
		switch result.Verdict {
		case VerdictNone, VerdictPortal:
			return result
		case VerdictSuspected:
			verdict = result
		}
	}
	// A network that only takes over DNS answers the relay's name with an
	// address of its own.
	if verdict.Verdict == VerdictUnknown && resolveErr == nil && len(resolved) != 0 && len(in.Relays) != 0 &&
		!slices.ContainsFunc(resolved, func(address netip.Addr) bool { return slices.Contains(in.Relays, address) }) {
		return Result{Verdict: VerdictSuspected}
	}
	return verdict
}

// relayAddresses keeps one IPv4 and one IPv6 address to probe.
func relayAddresses(all []netip.Addr) []netip.Addr {
	var picked []netip.Addr
	for _, want4 := range []bool{true, false} {
		for _, address := range all {
			if address.IsValid() && address.Unmap().Is4() == want4 {
				picked = append(picked, address.Unmap())
				break
			}
		}
	}
	return picked
}

// record keeps a new verdict, an unknown one keeping what was known, and
// tells the client of a change.
func (d *Detector) record(result Result, now time.Time) {
	d.mu.Lock()
	previous := d.state
	if result.Verdict == VerdictUnknown && previous.Verdict != VerdictNone {
		result = Result{Verdict: previous.Verdict, URL: previous.URL}
	}
	if result.Verdict == VerdictUnknown {
		result.Verdict = VerdictNone
	}
	next := State{Verdict: result.Verdict, URL: result.URL, Since: previous.Since, CheckedAt: now}
	if result.Verdict != previous.Verdict {
		next.Since = now
	}
	if result.Verdict == VerdictNone {
		next = State{Verdict: VerdictNone, CheckedAt: now}
	}
	d.state = next
	changed := next.Verdict != previous.Verdict || next.URL != previous.URL
	d.mu.Unlock()
	if changed && d.onChange != nil {
		d.onChange(next)
	}
}
