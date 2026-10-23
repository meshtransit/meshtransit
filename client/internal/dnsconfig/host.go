package dnsconfig

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"meshtransit.net/client/internal/netadmin"
)

type dnsAdministrator interface {
	ConfigureDNS(context.Context, netadmin.DNSConfig) error
	ResetDNS(context.Context) error
}

// ResolvedHost owns the systemd-resolved side of the DNS transaction. The
// privileged helper independently validates every endpoint and domain.
type ResolvedHost struct {
	mu       sync.Mutex
	admin    dnsAdministrator
	endpoint EndpointSource
	current  netadmin.DNSConfig
	isActive bool
	// dirty marks a configuration that failed part way: the link may hold
	// some of it, so turning DNS off must revert the link.
	dirty bool
}

// NewResolvedHost constructs the OS-facing DNS adapter.
func NewResolvedHost(admin dnsAdministrator, endpoint EndpointSource) (*ResolvedHost, error) {
	if admin == nil {
		return nil, errors.New("dnsconfig: dns administrator is required")
	}
	if endpoint == nil {
		return nil, errors.New("dnsconfig: endpoint source is required")
	}

	return &ResolvedHost{admin: admin, endpoint: endpoint}, nil
}

// Apply replaces all per-link DNS state, or reverts the link for a disabled
// plan. A failed replacement attempts to restore the previous complete state.
func (h *ResolvedHost) Apply(ctx context.Context, plan Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !plan.Enabled {
		if !h.isActive && !h.dirty {
			return nil
		}
		if err := h.admin.ResetDNS(ctx); err != nil {
			return fmt.Errorf("dnsconfig: reverting resolved link: %w", err)
		}
		h.current = netadmin.DNSConfig{}
		h.isActive = false
		h.dirty = false

		return nil
	}
	endpoint, ok := h.endpoint.Endpoint()
	if !ok {
		return errors.New("dnsconfig: resolver endpoint is not ready")
	}
	config, err := buildResolvedConfig(plan, endpoint)
	if err != nil {
		return err
	}
	if h.isActive && equalDNSConfig(h.current, config) {
		return nil
	}
	previous := cloneDNSConfig(h.current)
	wasActive := h.isActive
	if err := h.admin.ConfigureDNS(ctx, config); err != nil {
		h.dirty = true
		var rollbackErr error
		if wasActive {
			rollbackCtx, cancel := rollbackContext(ctx)
			rollbackErr = h.admin.ConfigureDNS(rollbackCtx, previous)
			cancel()
		}

		return errors.Join(
			fmt.Errorf("dnsconfig: configuring resolved link: %w", err),
			wrapRollbackError("resolved link", rollbackErr),
		)
	}
	h.current = cloneDNSConfig(config)
	h.isActive = true
	h.dirty = false

	return nil
}

func buildResolvedConfig(plan Plan, endpoint netadmin.DNSEndpoint) (netadmin.DNSConfig, error) {
	config := netadmin.DNSConfig{Endpoint: endpoint}
	seen := make(map[string]struct{}, len(plan.SearchDomains)+len(plan.Routes)+1)
	for _, domain := range plan.SearchDomains {
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		config.SearchDomains = append(config.SearchDomains, domain)
	}
	for _, route := range plan.Routes {
		if _, exists := seen[route.Suffix]; exists {
			continue
		}
		seen[route.Suffix] = struct{}{}
		config.RouteDomains = append(config.RouteDomains, route.Suffix)
	}
	if plan.RoutesAllNames() {
		if _, exists := seen["."]; !exists {
			config.RouteDomains = append(config.RouteDomains, ".")
		}
	}
	config.DefaultRoute = slices.Contains(config.RouteDomains, ".")
	if len(config.SearchDomains)+len(config.RouteDomains) == 0 {
		return netadmin.DNSConfig{}, errors.New("dnsconfig: enabled plan has no os routing domains")
	}

	return config, nil
}

func equalDNSConfig(left, right netadmin.DNSConfig) bool {
	return left.Endpoint == right.Endpoint && left.DefaultRoute == right.DefaultRoute &&
		slices.Equal(left.SearchDomains, right.SearchDomains) &&
		slices.Equal(left.RouteDomains, right.RouteDomains)
}

func cloneDNSConfig(config netadmin.DNSConfig) netadmin.DNSConfig {
	cloned := config
	cloned.SearchDomains = append([]string(nil), config.SearchDomains...)
	cloned.RouteDomains = append([]string(nil), config.RouteDomains...)

	return cloned
}

// MatchDomains returns the names a platform with split DNS sends the
// resolver for plan, as the desktop host does (its search and route
// domains), or nil when the resolver answers every name (an exit node or
// resolvers for every name).
func MatchDomains(plan Plan) []string {
	if plan.RoutesAllNames() {
		return nil
	}
	domains := make([]string, 0, len(plan.SearchDomains)+len(plan.Routes))
	for _, domain := range plan.SearchDomains {
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	for _, route := range plan.Routes {
		if !slices.Contains(domains, route.Suffix) {
			domains = append(domains, route.Suffix)
		}
	}
	return domains
}
