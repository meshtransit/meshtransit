package dnsconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

var ErrClosed = errors.New("dnsconfig: manager is closed")

const rollbackTimeout = 5 * time.Second

// Resolver atomically installs one local resolver plan. An unsuccessful call
// must leave the previous plan active. A disabled plan clears local records.
type Resolver interface {
	Apply(context.Context, Plan) error
	Close(context.Context) error
}

// HostConfigurator atomically installs the OS-facing DNS configuration. An
// unsuccessful call must restore the host configuration that preceded it. A
// disabled plan restores the host's original DNS behavior.
type HostConfigurator interface {
	Apply(context.Context, Plan) error
}

// Manager serializes DNS updates and coordinates rollback across the local
// resolver and the OS-facing configurator.
type Manager struct {
	mu       sync.Mutex
	resolver Resolver
	host     HostConfigurator
	current  Plan
	closed   bool
	logger   *slog.Logger
	// off is root's choice to keep the host's own DNS (DNS design D5b);
	// last is the map last applied, applied again when it changes, and
	// reapplied learns of that.
	off       atomic.Bool
	keeping   atomic.Bool // the last map left the host its own DNS
	last      *networkmap.Snapshot
	reapplied func(networkmap.Snapshot, bool, error)
	// appliedOff is the choice the last successful apply followed;
	// reapplying is set while a change of choice applies the last map.
	appliedOff bool
	reapplying bool
}

// SetLogger reports, from now on, routes from control a plan ignored.
func (m *Manager) SetLogger(logger *slog.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger = logger
}

// NewManager creates a DNS transaction manager from explicit backends.
func NewManager(resolver Resolver, host HostConfigurator) (*Manager, error) {
	if resolver == nil {
		return nil, errors.New("dnsconfig: resolver is required")
	}
	if host == nil {
		return nil, errors.New("dnsconfig: host configurator is required")
	}

	return &Manager{resolver: resolver, host: host}, nil
}

// Apply compiles and transactionally activates one network-map revision. The
// returned state is true only when both the local resolver and host DNS are
// configured for an enabled plan.
func (m *Manager) Apply(ctx context.Context, snapshot networkmap.Snapshot) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false, ErrClosed
	}
	kept := snapshot
	m.last = &kept

	return m.applyLocked(ctx, snapshot)
}

// applyLocked is Apply with m.mu held.
func (m *Manager) applyLocked(ctx context.Context, snapshot networkmap.Snapshot) (bool, error) {
	plan, err := Compile(snapshot)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	off := m.off.Load()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if plan.IgnoredRoutes > 0 && m.logger != nil {
		m.logger.Warn("dns routes from control ignored: a locally answered route for the root or a top-level name",
			"routes", plan.IgnoredRoutes)
	}
	previous := clonePlan(m.current)
	keeping := plan.Enabled && off && plan.Exit == nil
	m.keeping.Store(keeping)
	if !plan.Enabled {
		err := m.disableLocked(ctx, previous, plan)
		if err == nil {
			m.appliedOff = off
		}
		return false, err
	}
	if keeping {
		// The host keeps its own DNS; the mesh's names are still answered
		// on the resolver's address for whoever asks it.
		if err := m.host.Apply(ctx, Plan{}); err != nil {
			return false, fmt.Errorf("restoring host dns: %w", err)
		}
		if err := m.resolver.Apply(ctx, clonePlan(plan)); err != nil {
			return false, fmt.Errorf("configuring local dns resolver: %w", err)
		}
		m.current, m.appliedOff = Plan{}, off
		return false, nil
	}

	if err := m.resolver.Apply(ctx, clonePlan(plan)); err != nil {
		return false, fmt.Errorf("configuring local dns resolver: %w", err)
	}
	if err := m.host.Apply(ctx, clonePlan(plan)); err != nil {
		rollbackCtx, cancel := rollbackContext(ctx)
		rollbackErr := m.resolver.Apply(rollbackCtx, clonePlan(previous))
		cancel()
		return false, errors.Join(
			fmt.Errorf("configuring host dns: %w", err),
			wrapRollbackError("local resolver", rollbackErr),
		)
	}
	m.current, m.appliedOff = clonePlan(plan), off

	return true, nil
}

// SetUse sets root's choice (on by default): off, the host keeps its own
// DNS unless an exit node carries the Internet, whose kill switch admits no
// other DNS. While the last map was applied under the other choice, it is
// applied again, the newest map under the lock, so an older one never lands
// last; a failure is tried again on the next call.
func (m *Manager) SetUse(on bool) {
	if m == nil {
		return
	}
	m.off.Store(!on)
	m.mu.Lock()
	due := m.last != nil && !m.closed && !m.reapplying && m.appliedOff != !on
	if due {
		m.reapplying = true
	}
	reapplied := m.reapplied
	m.mu.Unlock()
	if !due {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		m.mu.Lock()
		var snapshot networkmap.Snapshot
		var err error
		configured := false
		applied := m.last != nil && !m.closed
		if applied {
			snapshot = *m.last
			configured, err = m.applyLocked(ctx, snapshot)
		}
		m.reapplying = false
		m.mu.Unlock()
		if applied && reapplied != nil {
			reapplied(snapshot, configured, err)
		}
	}()
}

// UsesMeshDNS reports whether MeshTransit answers the host's names: not
// when root turned it off, unless an exit node is in use.
func (m *Manager) UsesMeshDNS() bool { return m == nil || !m.keeping.Load() }

// OnReapply sets what learns of applying the last map again after SetUse.
func (m *Manager) OnReapply(reapplied func(networkmap.Snapshot, bool, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reapplied = reapplied
}

func (m *Manager) disableLocked(ctx context.Context, previous, disabled Plan) error {
	if err := m.host.Apply(ctx, clonePlan(disabled)); err != nil {
		return fmt.Errorf("restoring host dns: %w", err)
	}
	if err := m.resolver.Apply(ctx, clonePlan(disabled)); err != nil {
		rollbackCtx, cancel := rollbackContext(ctx)
		rollbackErr := m.host.Apply(rollbackCtx, clonePlan(previous))
		cancel()
		return errors.Join(
			fmt.Errorf("clearing local dns resolver: %w", err),
			wrapRollbackError("host dns", rollbackErr),
		)
	}
	m.current = clonePlan(disabled)

	return nil
}

// Reset restores the host's original DNS behavior while keeping the manager
// reusable for a later map or profile.
func (m *Manager) Reset(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	disabled := Plan{Revision: m.current.Revision}
	m.last = nil

	return m.disableLocked(ctx, clonePlan(m.current), disabled)
}

// Close restores host DNS before clearing the local resolver. Successful close
// is idempotent and permanently closes the manager.
func (m *Manager) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.last = nil
	disabled := Plan{Revision: m.current.Revision}
	if err := m.host.Apply(ctx, disabled); err != nil {
		return fmt.Errorf("restoring host dns during close: %w", err)
	}
	if err := m.resolver.Apply(ctx, disabled); err != nil {
		return fmt.Errorf("clearing local dns resolver during close: %w", err)
	}
	if err := m.resolver.Close(ctx); err != nil {
		return fmt.Errorf("closing local dns resolver: %w", err)
	}
	m.current = disabled
	m.closed = true

	return nil
}

func wrapRollbackError(component string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("rolling back %s: %w", component, err)
}

func rollbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
}

func clonePlan(plan Plan) Plan {
	cloned := plan
	cloned.DefaultResolvers = append([]netip.AddrPort(nil), plan.DefaultResolvers...)
	cloned.FallbackResolvers = append([]netip.AddrPort(nil), plan.FallbackResolvers...)
	if plan.Root != nil {
		root := *plan.Root
		root.Resolvers = append([]netip.AddrPort(nil), plan.Root.Resolvers...)
		cloned.Root = &root
	}
	cloned.Routes = make([]Route, len(plan.Routes))
	for index, route := range plan.Routes {
		cloned.Routes[index] = Route{
			Suffix:      route.Suffix,
			Resolvers:   append([]netip.AddrPort(nil), route.Resolvers...),
			Unavailable: route.Unavailable,
			FailOpen:    route.FailOpen,
		}
	}
	cloned.SearchDomains = append([]string(nil), plan.SearchDomains...)
	cloned.Hosts = make([]Host, len(plan.Hosts))
	for index, host := range plan.Hosts {
		cloned.Hosts[index] = Host{
			Name:      host.Name,
			Addresses: append([]netip.Addr(nil), host.Addresses...),
		}
	}
	cloned.Aliases = append([]Alias(nil), plan.Aliases...)
	cloned.Interior = append([]string(nil), plan.Interior...)
	cloned.Reverse = append([]Reverse(nil), plan.Reverse...)
	if plan.Exit != nil {
		exit := ExitDNS{Resolvers: append([]netip.AddrPort{}, plan.Exit.Resolvers...), IPv6: plan.Exit.IPv6}
		cloned.Exit = &exit
	}

	return cloned
}

// captiveResolver is a resolver that can send names to the network's own
// resolvers during a captive portal window.
type captiveResolver interface {
	SetCaptiveWindow(open bool)
}

// SetCaptiveWindow sends the names the exit node's resolver answers to the
// network's resolvers while open: a captive portal window root opened, whose
// portal the exit node cannot see (exit node design §17.5).
func (m *Manager) SetCaptiveWindow(open bool) {
	if m == nil {
		return
	}
	if resolver, ok := m.resolver.(captiveResolver); ok {
		resolver.SetCaptiveWindow(open)
	}
}
