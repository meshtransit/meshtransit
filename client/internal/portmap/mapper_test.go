package portmap

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// scriptedClient is a protocol client whose answers the test sets.
type scriptedClient struct {
	name Protocol
	mu   sync.Mutex
	err  error
	held bool
	ext  netip.AddrPort
	life time.Duration
	// calls record what the mapper asked for.
	maps     []uint16
	renewals int
	unmaps   []uint16
	checks   int
}

func (c *scriptedClient) protocol() Protocol { return c.name }

func (c *scriptedClient) mapPort(_ context.Context, gw Gateway, internal uint16, previous *Mapping) (Mapping, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maps = append(c.maps, internal)
	if previous != nil {
		c.renewals++
	}
	if c.err != nil {
		return Mapping{}, c.err
	}

	return Mapping{Protocol: c.name, Gateway: gw, Internal: internal, External: c.ext, Lifetime: c.life, Obtained: time.Now()}, nil
}

func (c *scriptedClient) unmap(_ context.Context, m Mapping) error {
	c.mu.Lock()
	c.unmaps = append(c.unmaps, m.Internal)
	c.mu.Unlock()

	return nil
}

func (c *scriptedClient) check(context.Context, Mapping) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++

	return c.held, nil
}

func (c *scriptedClient) set(update func(*scriptedClient)) {
	c.mu.Lock()
	update(c)
	c.mu.Unlock()
}

func (c *scriptedClient) counts() (maps, renewals, unmaps, checks int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.maps), c.renewals, len(c.unmaps), c.checks
}

type mapperFixture struct {
	t       *testing.T
	mapper  *Mapper
	pcp     *scriptedClient
	natpmp  *scriptedClient
	upnp    *scriptedClient
	gwMu    sync.Mutex
	gateway Gateway
	gwErr   error
	cancel  context.CancelFunc
	done    chan struct{}
}

func newMapperFixture(t *testing.T) *mapperFixture {
	t.Helper()
	f := &mapperFixture{
		t:       t,
		pcp:     &scriptedClient{name: ProtocolPCP, err: ErrUnsupported},
		natpmp:  &scriptedClient{name: ProtocolNATPMP, held: true, ext: netip.AddrPortFrom(testExternal, 41641), life: time.Hour},
		upnp:    &scriptedClient{name: ProtocolUPnP, err: ErrUnsupported},
		gateway: testGateway,
	}
	f.mapper = newMapper(Options{
		Gateway: func() (Gateway, error) {
			f.gwMu.Lock()
			defer f.gwMu.Unlock()
			return f.gateway, f.gwErr
		},
		Clock: time.Now,
	}, []client{f.pcp, f.natpmp, f.upnp})
	f.mapper.schedule = schedule{
		check: time.Hour, unavailable: time.Hour, failed: 20 * time.Millisecond,
		maxFailed: 50 * time.Millisecond, minRenew: 10 * time.Millisecond, release: time.Second,
	}

	return f
}

func (f *mapperFixture) start() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel, f.done = cancel, make(chan struct{})
	go func() {
		defer close(f.done)
		f.mapper.Run(ctx)
	}()
	f.t.Cleanup(f.stop)
}

func (f *mapperFixture) stop() {
	if f.cancel != nil {
		f.cancel()
		<-f.done
		f.cancel = nil
	}
}

// eventually waits until condition holds.
func (f *mapperFixture) eventually(what string, condition func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			f.t.Fatalf("timed out waiting for %s; status %+v", what, f.mapper.Status())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (f *mapperFixture) state(want string) func() bool {
	return func() bool { return f.mapper.Status().State == want }
}

func TestMapperFallsBackAndPublishesThePublicMapping(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.start()
	if _, ok := f.mapper.Candidate(); ok {
		t.Fatal("a candidate before any port was set")
	}
	f.mapper.SetPort(41641)
	f.eventually("mapped", f.state(StateMapped))
	select {
	case <-f.mapper.Changes():
	case <-time.After(time.Second):
		t.Fatal("no change signal for the new candidate")
	}
	candidate, ok := f.mapper.Candidate()
	if !ok || candidate != netip.AddrPortFrom(testExternal, 41641) {
		t.Fatalf("candidate %s %v", candidate, ok)
	}
	if status := f.mapper.Status(); status.Protocol != ProtocolNATPMP || status.ExpiresAt.IsZero() {
		t.Fatalf("status %+v", status)
	}
	if maps, _, _, _ := f.pcp.counts(); maps != 1 {
		t.Fatalf("pcp tried %d times", maps)
	}
	if maps, _, _, _ := f.upnp.counts(); maps != 0 {
		t.Fatal("upnp tried although nat-pmp worked")
	}

	f.stop()
	if _, _, unmaps, _ := f.natpmp.counts(); unmaps != 1 {
		t.Fatalf("stopping removed %d mappings", unmaps)
	}
	if _, ok := f.mapper.Candidate(); ok || f.mapper.Status().State != StateIdle {
		t.Fatal("a stopped mapper still offers a candidate")
	}
}

func TestMapperRenewsAtHalfLifetimeWithTheWorkingProtocolFirst(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.natpmp.set(func(c *scriptedClient) { c.life = 60 * time.Millisecond })
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("two renewals", func() bool {
		_, renewals, _, _ := f.natpmp.counts()
		return renewals >= 2
	})
	if maps, _, _, _ := f.pcp.counts(); maps != 1 {
		t.Fatalf("pcp asked again on renewal (%d times)", maps)
	}
}

func TestMapperDoubleNATIsNotACandidate(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.natpmp.set(func(c *scriptedClient) { c.ext = netip.MustParseAddrPort("100.72.9.1:41641") })
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("double nat", f.state(StateDoubleNAT))
	if _, ok := f.mapper.Candidate(); ok {
		t.Fatal("a shared-address mapping was offered as a candidate")
	}
}

func TestMapperFollowsPortAndGatewayChanges(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("mapped", f.state(StateMapped))

	f.mapper.SetPort(41700)
	f.eventually("remapped on the new port", func() bool {
		_, _, unmaps, _ := f.natpmp.counts()
		maps, _, _, _ := f.natpmp.counts()
		return unmaps == 1 && maps == 2
	})

	f.gwMu.Lock()
	f.gateway = Gateway{Addr: netip.MustParseAddr("10.0.0.1"), Local: netip.MustParseAddr("10.0.0.5")}
	f.gwMu.Unlock()
	f.mapper.NetworkChanged()
	f.eventually("remapped on the new gateway", func() bool {
		maps, _, unmaps, _ := f.natpmp.counts()
		return unmaps == 2 && maps == 3
	})

	f.gwMu.Lock()
	f.gwErr = ErrNoGateway
	f.gwMu.Unlock()
	f.mapper.NetworkChanged()
	f.eventually("unavailable without a gateway", f.state(StateUnavailable))
	if _, ok := f.mapper.Candidate(); ok {
		t.Fatal("a candidate without a gateway")
	}
	f.mapper.SetPort(0)
	f.eventually("idle without a port", f.state(StateIdle))
}

func TestMapperMapsAgainWhenTheGatewayLosesTheMapping(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("mapped", f.state(StateMapped))
	f.natpmp.set(func(c *scriptedClient) { c.held = false })
	f.mapper.NetworkChanged() // a network change checks the mapping now
	f.eventually("mapped again", func() bool {
		maps, _, _, checks := f.natpmp.counts()
		return checks >= 1 && maps >= 2
	})
}

func TestMapperStates(t *testing.T) {
	t.Parallel()
	unavailable := newMapperFixture(t)
	unavailable.natpmp.set(func(c *scriptedClient) { c.err = ErrUnsupported })
	unavailable.start()
	unavailable.mapper.SetPort(41641)
	unavailable.eventually("unavailable", unavailable.state(StateUnavailable))
	if code := unavailable.mapper.Status().Error; code != "unsupported" {
		t.Fatalf("code %q", code)
	}

	failed := newMapperFixture(t)
	failed.natpmp.set(func(c *scriptedClient) { c.err = errors.Join(ErrRefused, errFake) })
	failed.start()
	failed.mapper.SetPort(41641)
	failed.eventually("failed", failed.state(StateFailed))
	if code := failed.mapper.Status().Error; code != "refused" {
		t.Fatalf("code %q", code)
	}
	failed.natpmp.set(func(c *scriptedClient) { c.err = nil })
	failed.eventually("recovered after backoff", failed.state(StateMapped))
}

func TestBackoff(t *testing.T) {
	t.Parallel()
	for failures, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 9: 5 * time.Minute} {
		if got := backoff(30*time.Second, 5*time.Minute, failures); got != want {
			t.Errorf("%d failures: %s", failures, got)
		}
	}
}

func TestMapperCandidateFollowsTheCurrentPortAndExpiry(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("mapped", f.state(StateMapped))

	// A mapping for the previous port is never offered, even before the
	// mapper has replaced it.
	f.mapper.mu.Lock()
	f.mapper.port = 41700
	_, ok := f.mapper.candidateLocked()
	f.mapper.port = 41641
	f.mapper.mu.Unlock()
	if ok {
		t.Fatal("a mapping of another port was offered")
	}

	f.mapper.mu.Lock()
	expired := *f.mapper.mapping
	expired.Obtained = time.Now().Add(-2 * expired.Lifetime)
	f.mapper.mapping = &expired
	_, ok = f.mapper.candidateLocked()
	f.mapper.mu.Unlock()
	if ok {
		t.Fatal("an expired mapping was offered")
	}
}

func TestMapperStopsOfferingWhileRenewalsFail(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.natpmp.set(func(c *scriptedClient) { c.life = 200 * time.Millisecond })
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("mapped", f.state(StateMapped))
	if _, ok := f.mapper.Candidate(); !ok {
		t.Fatal("no candidate for the mapping")
	}
	// The gateway still holds the mapping, but renewals fail.
	f.natpmp.set(func(c *scriptedClient) { c.err = errors.Join(ErrRefused, errFake) })
	f.eventually("not offered while renewals fail", func() bool {
		_, ok := f.mapper.Candidate()
		return !ok && f.mapper.Status().State == StateMapped
	})
	f.eventually("given up after repeated failures", f.state(StateFailed))
	if _, _, unmaps, _ := f.natpmp.counts(); unmaps == 0 {
		t.Fatal("the abandoned mapping was not removed")
	}
}

func TestMapperSkipsHostsWithoutNAT(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.gateway = Gateway{Addr: netip.MustParseAddr("203.0.113.1"), Local: netip.MustParseAddr("203.0.113.20")}
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("unavailable", f.state(StateUnavailable))
	if status := f.mapper.Status(); status.Error != "no_nat" {
		t.Fatalf("status %+v", status)
	}
	if maps, _, _, _ := f.natpmp.counts(); maps != 0 {
		t.Fatal("a mapping request went to a public router")
	}
}

func TestMapperForgetsThePortBetweenSessions(t *testing.T) {
	t.Parallel()
	f := newMapperFixture(t)
	f.start()
	f.mapper.SetPort(41641)
	f.eventually("mapped", f.state(StateMapped))
	f.stop()
	maps, _, _, _ := f.natpmp.counts()
	f.start() // the next control session, before it knows its port
	time.Sleep(50 * time.Millisecond)
	if again, _, _, _ := f.natpmp.counts(); again != maps {
		t.Fatal("a new session mapped the previous session's port")
	}
}
