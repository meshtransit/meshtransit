package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/routesettings"
)

// routeOfferPoll is how often the daemon reads what the host offers to
// forward; a change reaches Core within this interval.
const routeOfferPoll = 5 * time.Second

// offeredRoutes is what the host offers to forward as a router (mtcp-v1
// §8.2): its advertised subnets while router mode is on, otherwise none.
// Unsafe or unreadable settings offer nothing.
func offeredRoutes(load func(string) (routesettings.Settings, error), path string, logger *slog.Logger) []netip.Prefix {
	settings, err := load(path)
	if err != nil {
		if logger != nil {
			logger.Warn("route settings unusable; offering no subnets", "error", err)
		}
		return []netip.Prefix{}
	}
	if !settings.RouterMode {
		return []netip.Prefix{}
	}
	return append([]netip.Prefix{}, settings.AdvertiseRoutes...)
}

// watchRouteOffer sends the host's offer at once and again after each
// change, until ctx ends.
func watchRouteOffer(ctx context.Context, load func(string) (routesettings.Settings, error), path string,
	interval time.Duration, logger *slog.Logger, offers chan<- []netip.Prefix,
) {
	var last []netip.Prefix
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if offer := offeredRoutes(load, path, logger); last == nil || !slices.Equal(last, offer) {
			select {
			case offers <- offer:
				last = offer
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
