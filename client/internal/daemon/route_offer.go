package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/routesettings"
)

// routeOfferPoll is how often the daemon reads what the host offers to
// forward; a change reaches Core within this interval.
const routeOfferPoll = 5 * time.Second

// offeredRoutes is what the host offers (mtcp-v1 §8.2): its advertised
// subnets while router mode is on, otherwise none, and whether exit mode is
// on. Unsafe or unreadable settings offer nothing.
func offeredRoutes(load func(string) (routesettings.Settings, error), path string,
	logger *slog.Logger,
) controlplane.HostOffer {
	settings, err := load(path)
	if err != nil {
		if logger != nil {
			logger.Warn("route settings unusable; offering no subnets and no exit node", "error", err)
		}
		return controlplane.HostOffer{Prefixes: []netip.Prefix{}}
	}
	offer := controlplane.HostOffer{Prefixes: []netip.Prefix{}, Exit: settings.ExitMode}
	if settings.RouterMode {
		offer.Prefixes = append(offer.Prefixes, settings.AdvertiseRoutes...)
	}
	return offer
}

// watchRouteOffer sends the host's offer at once and again after each
// change, until ctx ends.
func watchRouteOffer(ctx context.Context, load func(string) (routesettings.Settings, error), path string,
	interval time.Duration, logger *slog.Logger, offers chan<- controlplane.HostOffer,
) {
	var last *controlplane.HostOffer
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if offer := offeredRoutes(load, path, logger); last == nil || !last.Equal(offer) {
			select {
			case offers <- offer:
				last = &offer
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
