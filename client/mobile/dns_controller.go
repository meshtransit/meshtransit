package mobile

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/underlay"
)

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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsReapplyTimeout)
	defer cancel()
	if _, err := c.manager.Apply(ctx, *c.last); err != nil {
		c.logger.Warn("applying dns again failed; the next map retries", "error", err)
	}
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
		// the resolver, without a plan, asks the networks' DNS servers.
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
