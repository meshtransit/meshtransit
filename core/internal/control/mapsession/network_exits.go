package mapsession

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// Bounds of the Exit Pools of one map (mtcp-v1 §7.7).
const (
	MaximumExitPools      = 64
	MaximumExitCandidates = 16
	MaximumExitProbes     = 8
	MaximumExitUpstreams  = 4
)

// ExitProbe is an Internet address and TCP port an exit node checks.
type ExitProbe struct {
	Address netip.Addr
	Port    uint16
}

// ExitPool is one active Exit Pool of the Network as maps see it.
type ExitPool struct {
	Pool                 int64 // internal reference
	Ref                  string
	Name                 string
	SMTPAllowed          bool
	ConntrackPerConsumer int
	DNSUpstreams         []netip.Addr
	Probes               []ExitProbe
	// Elected is true once Core elected the pool's primary (schema 204):
	// then Primary is its Device (0: no exit node can serve), and before it
	// the first active exit node by priority is.
	Elected bool
	Primary int64
	// Spread pools give each consumer its own exit node of Serving, the
	// Devices Core elected to serve (schema 210), hashed with Salt; Spread
	// is false while MESHTRANSIT_EXIT_SPREAD_ENABLED is off.
	Spread  bool
	Salt    [16]byte
	Serving []int64
	// CaptiveOff refuses captive portal windows on the pool's consumers
	// (schema 211); before it no pool does.
	CaptiveOff bool
}

// ExitNode is one exit node of an active pool, with the facts that decide
// whether it can serve.
type ExitNode struct {
	Pool           int64
	Device         int64
	NodeID         node.ID
	Priority       int
	Active         bool // false: draining
	WorkspaceOwned bool
	Offered        bool
}

// ExitRule is one rule of the active release whose destination is an Exit
// Pool, its source named by selector.
type ExitRule struct {
	ID         policy.RuleID
	SourceKind SelectorKind
	SourceRef  int64
	Pool       int64
	Protocol   policy.Protocol
	Ports      []policy.PortRange
}

// ExitPoolRoute is one Exit Pool a consumer may send its Internet traffic
// through. Its Status is RouteServed, RouteUnserved or RouteCapacity.
type ExitPoolRoute struct {
	Ref        string
	Name       string
	Candidates []node.ID
	Primary    node.ID // zero: none
	Generation int64
	Status     RouteStatus
	// Spread is true when Primary is the consumer's own exit node of a
	// spread pool and Candidates its own order (exit node design §16.4).
	Spread bool
	// Draining are the candidates an administrator is taking out of the
	// pool.
	Draining []node.ID
	// CaptiveOff refuses captive portal windows on the consumer while it
	// uses the pool (exit node design §17.4).
	CaptiveOff bool
}

// ServedExit is the Exit Pool an exit node forwards to the Internet for.
type ServedExit struct {
	Ref                  string
	Probes               []ExitProbe
	ConntrackPerConsumer int
	SMTPAllowed          bool
	DNSUpstreams         []netip.Addr
}

// ExitInbound admits the consumers of one rule to the Internet through the
// served pool: the exit node sends it with the destinations 0.0.0.0/0 and
// ::/0, and subtracts what is not the Internet itself.
type ExitInbound struct {
	Sources  []node.ID
	Protocol policy.Protocol
	Ports    []policy.PortRange
}

type exitPoolEntry struct {
	pool    ExitPool
	nodes   []ExitNode // by priority, then Device
	primary ExitNode   // the elected or first active exit node; zero Device: none
}

// Exits returns the Exit Pools the Device may use, sorted by reference.
func (view RouteView) Exits() []ExitPoolRoute {
	cloned := make([]ExitPoolRoute, len(view.exits))
	for index, route := range view.exits {
		route.Candidates, route.Draining = slices.Clone(route.Candidates), slices.Clone(route.Draining)
		cloned[index] = route
	}
	return cloned
}

// ServedExits returns the Exit Pool the Device serves: at most one.
func (view RouteView) ServedExits() []ServedExit {
	cloned := make([]ServedExit, len(view.servedExits))
	for index, served := range view.servedExits {
		served.Probes, served.DNSUpstreams = slices.Clone(served.Probes), slices.Clone(served.DNSUpstreams)
		cloned[index] = served
	}
	return cloned
}

// ExitInbound returns the traffic the Device admits to the Internet as an
// exit node.
func (view RouteView) ExitInbound() []ExitInbound {
	cloned := make([]ExitInbound, len(view.exitInbound))
	for index, rule := range view.exitInbound {
		rule.Sources, rule.Ports = slices.Clone(rule.Sources), slices.Clone(rule.Ports)
		cloned[index] = rule
	}
	return cloned
}

// indexExits validates and indexes the Network's Exit Pools into index.
// Rules naming an unknown pool grant nothing; exit nodes of an unknown pool
// are ignored. A Device is an exit node of one pool at most.
func (index *routeIndex) indexExits(params NetworkPolicyParams) bool {
	if len(params.ExitPools) > MaximumExitPools {
		return false
	}
	index.poolList, index.exitNodes = cloneExitPools(params.ExitPools), cloneExitNodes(params.ExitNodes)
	index.exitRules = cloneExitRules(params.ExitRules)
	index.pools, index.byPool = make(map[int64]*exitPoolEntry, len(index.poolList)), make(map[int64][]int)
	index.exitOf = make(map[int64]int64)
	for _, value := range index.poolList {
		if value.Pool <= 0 || value.Ref == "" || len(value.Ref) > 64 || value.Name == "" || value.Primary < 0 ||
			(!value.Elected && value.Primary != 0) || value.ConntrackPerConsumer <= 0 ||
			len(value.Serving) > MaximumExitCandidates || slices.ContainsFunc(value.Serving, func(device int64) bool {
			return device <= 0
		}) {
			return false
		}
		if _, duplicate := index.pools[value.Pool]; duplicate {
			return false
		}
		index.pools[value.Pool] = &exitPoolEntry{pool: value}
	}
	for _, exitNode := range index.exitNodes {
		if exitNode.Device <= 0 || !exitNode.NodeID.IsValid() {
			return false
		}
		entry := index.pools[exitNode.Pool]
		if entry == nil {
			continue
		}
		if _, duplicate := index.exitOf[exitNode.Device]; duplicate {
			return false
		}
		entry.nodes = append(entry.nodes, exitNode)
		index.exitOf[exitNode.Device] = exitNode.Pool
		index.nodes[exitNode.Device] = exitNode.NodeID
	}
	for _, entry := range index.pools {
		slices.SortFunc(entry.nodes, func(first, second ExitNode) int {
			return cmp.Or(cmp.Compare(first.Priority, second.Priority), cmp.Compare(first.Device, second.Device))
		})
		entry.primary = exitPoolPrimary(entry.pool, entry.nodes)
	}
	for position, rule := range index.exitRules {
		if !rule.ID.IsValid() || !rule.SourceKind.valid() || rule.SourceRef <= 0 {
			return false
		}
		if _, known := index.pools[rule.Pool]; known {
			index.byPool[rule.Pool] = append(index.byPool[rule.Pool], position)
		}
	}
	return true
}

// poolConsumers lists each pool's consumers in a fixed order, whatever their
// liveness or membership deadlines, without its own exit nodes.
func (index *routeIndex) poolConsumers() map[int64][]int64 {
	byPool := make(map[int64][]int64, len(index.pools))
	for pool, entry := range index.pools {
		var consumers []int64
		for _, position := range index.byPool[pool] {
			rule := index.exitRules[position]
			if rule.SourceKind == SelectorDevice {
				consumers = append(consumers, rule.SourceRef)
				continue
			}
			consumers = append(consumers, index.members(rule.SourceKind, rule.SourceRef)...)
		}
		slices.Sort(consumers)
		consumers = slices.Compact(consumers)
		byPool[pool] = slices.DeleteFunc(consumers, func(consumer int64) bool {
			return slices.ContainsFunc(entry.nodes, func(exitNode ExitNode) bool { return exitNode.Device == consumer })
		})
	}
	return byPool
}

// exitServes reports whether an exit node can serve its pool now: its
// Device is live, Workspace-owned and offers to be an exit node itself.
func (inner *networkPolicy) exitServes(exitNode ExitNode, now time.Time) bool {
	return exitNode.Device > 0 && exitNode.WorkspaceOwned && exitNode.Offered && inner.live(exitNode.Device, now)
}

// consumerExits adds the Exit Pools self may use: those an active rule
// grants it, never the pool it is an exit node of. Their exit nodes share
// the routers' part of the peer limit with the Sites' routers in routers.
func (inner *networkPolicy) consumerExits(view *RouteView, self int64, now time.Time,
	routers map[node.ID]struct{}) {
	index := inner.routes
	own, isExitNode := index.exitOf[self]
	granted := make(map[int64]struct{})
	for _, rule := range index.exitRules {
		if _, known := index.pools[rule.Pool]; !known || (isExitNode && rule.Pool == own) {
			continue
		}
		if _, done := granted[rule.Pool]; done || !inner.selects(rule.SourceKind, rule.SourceRef, self, now) {
			continue
		}
		granted[rule.Pool] = struct{}{}
	}
	pools := make([]ExitPoolRoute, 0, len(granted))
	capacity := make(map[string]bool, len(granted))
	for pool := range granted {
		entry := index.pools[pool]
		route := ExitPoolRoute{Ref: entry.pool.Ref, Name: entry.pool.Name, Generation: index.revision,
			Status: RouteUnserved, CaptiveOff: entry.pool.CaptiveOff}
		for _, exitNode := range entry.nodes {
			route.Candidates = append(route.Candidates, exitNode.NodeID)
			if !exitNode.Active {
				route.Draining = append(route.Draining, exitNode.NodeID)
			}
		}
		if entry.pool.Spread && inner.spreadRoute(&route, entry, self, now) {
			pools = append(pools, route)
			continue
		}
		if primary := entry.primary; primary.Device > 0 {
			route.Primary = primary.NodeID
			if inner.exitServes(primary, now) {
				route.Status = RouteServed
				position, _ := slices.BinarySearch(index.static[primary.Device], self)
				capacity[route.Ref] = position >= index.consumers
			}
		}
		pools = append(pools, route)
	}
	slices.SortFunc(pools, func(first, second ExitPoolRoute) int { return cmp.Compare(first.Ref, second.Ref) })
	for _, route := range pools {
		if route.Status == RouteServed && capacity[route.Ref] {
			route.Status = RouteCapacity
		}
		added := 0
		for _, candidate := range route.Candidates {
			if _, known := routers[candidate]; !known {
				added++
			}
		}
		// A pool without exit nodes cannot be sent (mtcp-v1 §7.7).
		if len(route.Candidates) == 0 {
			continue
		}
		if len(view.exits) == MaximumExitPools || len(route.Candidates) > MaximumExitCandidates ||
			len(routers)+added > index.routerLimit {
			view.omitted++
			continue
		}
		for _, candidate := range route.Candidates {
			routers[candidate] = struct{}{}
		}
		view.exits = append(view.exits, route)
	}
	for _, route := range view.exits {
		for _, candidate := range route.Candidates {
			if device, known := inner.byNode[candidate]; known && inner.live(device, now) {
				view.exitNodes = append(view.exitNodes, candidate)
			}
		}
	}
}

// servedExits adds the pool self serves as an exit node and the traffic it
// admits to the Internet: from its consumers within the peer limit.
func (inner *networkPolicy) servedExits(view *RouteView, self int64, now time.Time) {
	index := inner.routes
	pool, isExitNode := index.exitOf[self]
	if !isExitNode {
		return
	}
	entry := index.pools[pool]
	own := ExitNode{}
	for _, exitNode := range entry.nodes {
		if exitNode.Device == self {
			own = exitNode
		}
	}
	if !inner.exitServes(own, now) {
		return
	}
	value := entry.pool
	view.servedExits = []ServedExit{{Ref: value.Ref, Probes: slices.Clone(value.Probes),
		ConntrackPerConsumer: value.ConntrackPerConsumer, SMTPAllowed: value.SMTPAllowed,
		DNSUpstreams: slices.Clone(value.DNSUpstreams)}}
	static := index.static[self]
	for _, position := range index.byPool[pool] {
		rule := index.exitRules[position]
		var sources []node.ID
		_ = inner.eachSelected(rule.SourceKind, rule.SourceRef, now, func(consumer int64) error {
			at, found := slices.BinarySearch(static, consumer)
			if consumer != self && found && at < index.consumers && inner.live(consumer, now) {
				sources = append(sources, inner.devices[consumer].NodeID)
			}
			return nil
		})
		if len(sources) == 0 {
			continue
		}
		slices.SortFunc(sources, compareNodeIDs)
		sources = slices.Compact(sources)
		view.exitInbound = append(view.exitInbound, ExitInbound{Sources: sources, Protocol: rule.Protocol,
			Ports: slices.Clone(rule.Ports)})
		view.exitConsumers = append(view.exitConsumers, sources...)
	}
}

// exitPoolPrimary is the elected exit node while it is an active exit node
// of the pool, none when Core elected none, and otherwise the first active
// exit node by priority: the election lags a change of exit nodes by one
// sweep, and an elected Device that left the pool is no primary.
func exitPoolPrimary(pool ExitPool, nodes []ExitNode) ExitNode {
	if pool.Elected {
		if pool.Primary == 0 {
			return ExitNode{}
		}
		for _, exitNode := range nodes {
			if exitNode.Device == pool.Primary && exitNode.Active {
				return exitNode
			}
		}
	}
	for _, exitNode := range nodes {
		if exitNode.Active {
			return exitNode
		}
	}
	return ExitNode{}
}

func (index *routeIndex) equalExits(other *routeIndex) bool {
	return slices.EqualFunc(index.poolList, other.poolList, equalExitPool) &&
		slices.Equal(index.exitNodes, other.exitNodes) &&
		slices.EqualFunc(index.exitRules, other.exitRules, func(first, second ExitRule) bool {
			return first.ID == second.ID && first.SourceKind == second.SourceKind &&
				first.SourceRef == second.SourceRef && first.Pool == second.Pool &&
				first.Protocol == second.Protocol && slices.Equal(first.Ports, second.Ports)
		})
}

func equalExitPool(first, second ExitPool) bool {
	return first.Pool == second.Pool && first.Ref == second.Ref && first.Name == second.Name &&
		first.SMTPAllowed == second.SMTPAllowed && first.ConntrackPerConsumer == second.ConntrackPerConsumer &&
		slices.Equal(first.DNSUpstreams, second.DNSUpstreams) && slices.Equal(first.Probes, second.Probes) &&
		first.Elected == second.Elected && first.Primary == second.Primary && first.Spread == second.Spread &&
		first.Salt == second.Salt && slices.Equal(first.Serving, second.Serving) &&
		first.CaptiveOff == second.CaptiveOff
}

func equalExitPoolRoute(first, second ExitPoolRoute) bool {
	return first.Ref == second.Ref && first.Name == second.Name && slices.Equal(first.Candidates, second.Candidates) &&
		first.Primary == second.Primary && first.Generation == second.Generation && first.Status == second.Status &&
		first.Spread == second.Spread && slices.Equal(first.Draining, second.Draining) &&
		first.CaptiveOff == second.CaptiveOff
}

func equalServedExit(first, second ServedExit) bool {
	return first.Ref == second.Ref && slices.Equal(first.Probes, second.Probes) &&
		first.ConntrackPerConsumer == second.ConntrackPerConsumer && first.SMTPAllowed == second.SMTPAllowed &&
		slices.Equal(first.DNSUpstreams, second.DNSUpstreams)
}

func equalExitInbound(first, second ExitInbound) bool {
	return slices.Equal(first.Sources, second.Sources) && first.Protocol == second.Protocol &&
		slices.Equal(first.Ports, second.Ports)
}

func cloneExitPools(pools []ExitPool) []ExitPool {
	cloned := make([]ExitPool, len(pools))
	for index, pool := range pools {
		pool.DNSUpstreams, pool.Probes = slices.Clone(pool.DNSUpstreams), slices.Clone(pool.Probes)
		pool.Serving = slices.Clone(pool.Serving)
		cloned[index] = pool
	}
	return cloned
}

func cloneExitNodes(nodes []ExitNode) []ExitNode { return slices.Clone(nodes) }

func cloneExitRules(rules []ExitRule) []ExitRule {
	cloned := make([]ExitRule, len(rules))
	for index, rule := range rules {
		rule.Ports = slices.Clone(rule.Ports)
		cloned[index] = rule
	}
	return cloned
}
