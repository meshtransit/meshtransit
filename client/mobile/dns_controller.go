package mobile

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/underlay"
)

// failuresAsNXDOMAIN answers a zone's failures NXDOMAIN on Android, whose
// MIUI builds ask Google's DNS after SERVFAIL or REFUSED (DNS design D1b §20);
// iOS keeps them. Tests change it.
var failuresAsNXDOMAIN = runtime.GOOS == "android"

// dnsReapplyTimeout bounds applying the last map again after a local change.
const dnsReapplyTimeout = 10 * time.Second

// dnsController is the runtime's DNS controller on a phone (DNS design D4):
// the map's DNS answered by the in-process resolver, and the VPN
// interface's DNS pointed at it. It keeps the last map, applied again when
// the person turns MeshTransit DNS on or off or the platform first reports
// its networks' resolvers.
type dnsController struct {
	mu       sync.Mutex
	manager  *dnsconfig.Manager
	resolver *dnsconfig.PacketResolver
	last     *networkmap.Snapshot
	logger   *slog.Logger
	// use is the person's choice: MeshTransit answers the device's names.
	use *atomic.Bool
	// reapplied, when set, learns what came of applying the last map again.
	reapplied func(networkmap.Snapshot, bool, error)
}

// newDNSController builds the resolver and the host side for opener.
func newDNSController(opener *platformTUN, logger *slog.Logger) (*dnsController, error) {
	use := &atomic.Bool{}
	use.Store(true)
	resolver := dnsconfig.NewPacketResolver(dnsconfig.PacketResolverOptions{
		Address:           resolverAddress,
		MaxUDPResponse:    opener.mtu - 28,
		ExitRouted:        opener.exitRouted.Load,
		NetworkGeneration: underlay.ReportedGeneration,
		// Some Android builds ask Google's DNS after SERVFAIL or REFUSED,
		// skipping a filter or a zone that fails closed (DNS design D1b §20).
		FailuresAsNXDOMAIN: failuresAsNXDOMAIN,
	})
	manager, err := dnsconfig.NewManager(
		&choiceResolver{resolver: resolver, use: use},
		&mobileDNSHost{opener: opener, use: use},
	)
	if err != nil {
		return nil, err
	}
	manager.SetLogger(logger)
	opener.answer = resolver.Answer
	return &dnsController{manager: manager, resolver: resolver, logger: logger, use: use}, nil
}

// Apply applies the map's DNS and keeps the map for a later local change.
func (c *dnsController) Apply(ctx context.Context, snapshot networkmap.Snapshot) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = &snapshot
	return c.manager.Apply(ctx, snapshot)
}

// Reset takes the map's DNS away until the next map.
func (c *dnsController) Reset(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = nil
	return c.manager.Reset(ctx)
}

// Close ends a run of the runtime: the map's DNS goes, while the resolver
// stays for the next Start. Only the Engine's Close stops it (shutdown).
func (c *dnsController) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = nil
	return c.manager.Reset(ctx)
}

// shutdown stops the resolver for good, when the Engine closes.
func (c *dnsController) shutdown() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = nil
	ctx, cancel := context.WithTimeout(context.Background(), dnsReapplyTimeout)
	defer cancel()
	return c.manager.Close(ctx)
}

// setUse records the person's choice and applies the last map again.
func (c *dnsController) setUse(on bool) {
	if c.use.Swap(on) != on {
		go c.reapply()
	}
}

// reapply applies the last map again, for a change of local state.
func (c *dnsController) reapply() {
	snapshot, reapplied, configured, ok, err := c.applyLastAgain()
	if ok && reapplied != nil {
		// Outside the lock: the daemon hands the evidence to the session.
		reapplied(snapshot, configured, err)
	}
}

// applyLastAgain applies the last map again; ok is false without one.
func (c *dnsController) applyLastAgain() (networkmap.Snapshot, func(networkmap.Snapshot, bool, error), bool, bool,
	error,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		return networkmap.Snapshot{}, nil, false, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsReapplyTimeout)
	defer cancel()
	configured, err := c.manager.Apply(ctx, *c.last)
	if err != nil {
		c.logger.Warn("applying dns again failed; the next map retries", "error", err)
	}
	return *c.last, c.reapplied, configured, true, err
}

// OnReapply sets what learns of applying the last map again: the daemon,
// which reports the DNS now applied to Core (DNS design D1b Q7).
func (c *dnsController) OnReapply(reapplied func(networkmap.Snapshot, bool, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reapplied = reapplied
}

// SetResolverLiveness makes the resolver ask last the resolver Devices that
// stopped answering (DNS design D1b §5.6).
func (c *dnsController) SetResolverLiveness(liveness dnsconfig.ResolverLiveness) {
	c.manager.SetResolverLiveness(liveness)
}

// ResolverHealth returns how the resolver sees the zones' resolvers (DNS
// design D1b §9).
func (c *dnsController) ResolverHealth() ([]controlplane.ResolverHealth, bool) {
	return c.manager.ResolverHealth()
}

// UsesMeshDNS reports the person's choice: MeshTransit answers the device's
// names (DNS design D1b Q7: off is reported to Core as user_off).
func (c *dnsController) UsesMeshDNS() bool { return c.use.Load() }

// SetInfrastructureNames names MeshTransit's own infrastructure for the
// root zone to leave to the network (DNS design D1b §5.8).
func (c *dnsController) SetInfrastructureNames(names []string) {
	c.manager.SetInfrastructureNames(names)
}

// stats returns the resolver's counts.
func (c *dnsController) stats() dnsconfig.PacketResolverStats { return c.resolver.Stats() }

// choiceResolver gives the resolver the map's plan while the person uses
// MeshTransit DNS, and only the exit node's part otherwise: off means the
// mesh's names are not answered, while the Internet's still go to the exit
// node as long as the device routes through one (DNS design D4 §3.8).
type choiceResolver struct {
	resolver *dnsconfig.PacketResolver
	use      *atomic.Bool
}

func (r *choiceResolver) Apply(ctx context.Context, plan dnsconfig.Plan) error {
	if !r.use.Load() {
		plan = dnsconfig.Plan{Revision: plan.Revision, Enabled: plan.Exit != nil, Exit: plan.Exit}
	}
	return r.resolver.Apply(ctx, plan)
}

func (r *choiceResolver) Close(ctx context.Context) error { return r.resolver.Close(ctx) }

func (r *choiceResolver) SetResolverLiveness(liveness dnsconfig.ResolverLiveness) {
	r.resolver.SetResolverLiveness(liveness)
}

func (r *choiceResolver) SetInfrastructureNames(names []string) {
	r.resolver.SetInfrastructureNames(names)
}

func (r *choiceResolver) ResolverHealth() []controlplane.ResolverHealth {
	return r.resolver.ResolverHealth()
}

// mobileDNSHost points the VPN interface's DNS at the resolver (DNS design
// D4 §3.4): while the plan is enabled, the person uses MeshTransit DNS, and
// the platform has reported its networks' resolvers, which the resolver
// sends the Internet's names to. Once on, a moment without them (no
// network) does not take it off. The exit route keeps it on regardless.
type mobileDNSHost struct {
	opener *platformTUN
	use    *atomic.Bool
}

func (h *mobileDNSHost) Apply(ctx context.Context, plan dnsconfig.Plan) error {
	if !plan.Enabled {
		// A map without DNS, or the runtime stopping: the interface keeps
		// its DNS rather than being made again just before it closes, and
		// the resolver, without a plan, asks the networks' DNS servers. A
		// map that carries empty DNS (the Device is unmanaged, D5b) takes
		// it off the interface: the phone keeps its own DNS.
		if plan.Configured {
			return h.opener.setDNS(ctx, mobileDNS{})
		}
		return nil
	}
	h.opener.mu.Lock()
	alreadyOn := h.opener.dnsWanted.on
	h.opener.mu.Unlock()
	wanted := mobileDNS{}
	if plan.Enabled && h.use.Load() && (alreadyOn || len(underlay.ReportedResolvers()) != 0) {
		wanted = mobileDNS{
			on: true, search: append([]string(nil), plan.SearchDomains...), match: dnsconfig.MatchDomains(plan),
		}
	}
	return h.opener.setDNS(ctx, wanted)
}

// The phone's resolver orders resolver Devices by liveness, as the desktop's
// does: a refactor that loses a link fails the build.
var (
	_ interface {
		SetResolverLiveness(dnsconfig.ResolverLiveness)
	} = (*dnsController)(nil)
	_ interface {
		SetResolverLiveness(dnsconfig.ResolverLiveness)
	} = (*choiceResolver)(nil)
	_ interface{ SetInfrastructureNames([]string) } = (*dnsController)(nil)
	_ interface{ UsesMeshDNS() bool }               = (*dnsController)(nil)
	_ interface {
		ResolverHealth() ([]controlplane.ResolverHealth, bool)
	} = (*dnsController)(nil)
	_ interface{ SetInfrastructureNames([]string) } = (*choiceResolver)(nil)
	_ interface {
		OnReapply(func(networkmap.Snapshot, bool, error))
	} = (*dnsController)(nil)
)
