package dnsconfig

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"meshtransit.net/client/internal/underlay"
)

// minPacketResponse is the smallest answer cap: a DNS message over UDP may
// always be 512 bytes.
const minPacketResponse = defaultUDPSize

// PacketResolverOptions configures a PacketResolver.
type PacketResolverOptions struct {
	// Address is where the platform sends the questions; a plan that
	// forwards to it is refused, as it would ask itself.
	Address netip.Addr
	// MaxUDPResponse caps every answer, below the interface MTU: a larger
	// one is sent truncated. Zero means the EDNS limit alone.
	MaxUDPResponse int
	// ExitRouted reports whether the host's Internet routes go into the
	// mesh now, whatever the plan says (DNS design D4 §3.3).
	ExitRouted func() bool
	// NetworkResolvers lists the resolvers of the host's networks, asked for
	// names no route covers; nil uses underlay.NetworkResolvers.
	NetworkResolvers func() []netip.AddrPort
	// NetworkGeneration changes whenever NetworkResolvers would return
	// other resolvers; nil keeps them for networkResolverTTL.
	NetworkGeneration func() uint64
}

// PacketResolverStats counts the questions a PacketResolver answered.
type PacketResolverStats struct {
	Queries   uint64
	Failures  uint64
	Truncated uint64
}

// PacketResolver answers DNS messages in process, for a platform whose VPN
// hands the client raw packets and has no split DNS (Android): it answers
// every name, the mesh's as Server does and any other from the host's
// network resolvers (DNS design D4 §3.3). It never answers a captive portal
// window: the network's resolvers would then answer the exit node's names.
type PacketResolver struct {
	engine  *resolverEngine
	address netip.AddrPort
	maxUDP  int
	plan    atomic.Pointer[Plan]
	mu      sync.Mutex
	closed  atomic.Bool

	queries, failures, truncated atomic.Uint64
}

var _ Resolver = (*PacketResolver)(nil)

// NewPacketResolver returns a resolver with a disabled plan.
func NewPacketResolver(options PacketResolverOptions) *PacketResolver {
	engine := newResolverEngine()
	engine.fullResolver = true
	engine.exitRouted = options.ExitRouted
	engine.networkGeneration = options.NetworkGeneration
	if options.NetworkResolvers != nil {
		engine.networkResolvers = options.NetworkResolvers
	} else {
		engine.networkResolvers = underlay.NetworkResolvers
	}
	maxUDP := options.MaxUDPResponse
	if maxUDP != 0 {
		maxUDP = max(maxUDP, minPacketResponse)
	}
	resolver := &PacketResolver{engine: engine, maxUDP: maxUDP}
	if options.Address.IsValid() {
		resolver.address = netip.AddrPortFrom(options.Address.Unmap(), 53)
	}
	disabled := Plan{}
	resolver.plan.Store(&disabled)
	return resolver
}

// Apply publishes plan for the questions that follow. A disabled plan still
// answers: names go to the host's network resolvers, or to none while the
// Internet is routed into the mesh.
func (r *PacketResolver) Apply(ctx context.Context, plan Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return ErrClosed
	}
	if r.address.IsValid() && resolverLoop(plan, r.address) {
		return errors.New("dnsconfig: resolver plan points back to the local endpoint")
	}
	published := clonePlan(plan)
	r.plan.Store(&published)
	return nil
}

// Answer answers one DNS message that arrived over UDP; nil means no answer
// is sent (the message is not one to answer).
func (r *PacketResolver) Answer(ctx context.Context, query []byte) []byte {
	r.queries.Add(1)
	if r.closed.Load() {
		return nil
	}
	if len(query) < 12 || len(query) > maxQueryBytes {
		r.failures.Add(1)
		return nil
	}
	plan := r.plan.Load()
	response, err := r.engine.resolve(ctx, *plan, query, "udp")
	if err != nil {
		r.failures.Add(1)
	}
	if len(response) == 0 {
		return nil
	}
	if r.maxUDP != 0 && len(response) > r.maxUDP {
		limited, truncateErr := truncatedResponse(response)
		if truncateErr != nil || len(limited) > r.maxUDP {
			r.failures.Add(1)
			return nil
		}
		response = limited
	}
	if isTruncated(response) {
		r.truncated.Add(1)
	}
	return response
}

// Close stops publishing plans; questions are no longer answered.
func (r *PacketResolver) Close(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed.Store(true)
	disabled := Plan{}
	r.plan.Store(&disabled)
	return nil
}

// Stats returns the counts so far.
func (r *PacketResolver) Stats() PacketResolverStats {
	return PacketResolverStats{
		Queries: r.queries.Load(), Failures: r.failures.Load(), Truncated: r.truncated.Load(),
	}
}
