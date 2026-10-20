package dnsconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
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
	plan, err := Compile(snapshot)
	if err != nil {
		return false, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if plan.IgnoredRoutes > 0 && m.logger != nil {
		m.logger.Warn("dns routes from control ignored: a locally answered route for the root or a top-level name",
			"routes", plan.IgnoredRoutes)
	}
	previous := clonePlan(m.current)
	if !plan.Enabled {
		return false, m.disableLocked(ctx, previous, plan)
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
	m.current = clonePlan(plan)

	return true, nil
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
	cloned.Routes = make([]Route, len(plan.Routes))
	for index, route := range plan.Routes {
		cloned.Routes[index] = Route{
			Suffix:    route.Suffix,
			Resolvers: append([]netip.AddrPort(nil), route.Resolvers...),
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
	cloned.Reverse = append([]Reverse(nil), plan.Reverse...)
	if plan.Exit != nil {
		exit := ExitDNS{Resolvers: append([]netip.AddrPort{}, plan.Exit.Resolvers...), IPv6: plan.Exit.IPv6}
		cloned.Exit = &exit
	}

	return cloned
}
