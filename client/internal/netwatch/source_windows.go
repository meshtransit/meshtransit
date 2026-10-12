//go:build windows

package netwatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"meshtransit.net/client/internal/winadapter"
)

// notifySource wakes on IP interface, unicast address and route changes
// (NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
// NotifyRouteChange2). Changes on the MeshTransit adapter are dropped here:
// meshd makes them itself whenever the map changes.
type notifySource struct {
	signals chan struct{}
	done    chan struct{}
	// ownLUID is the MeshTransit adapter's LUID, 0 while it does not exist.
	// Notifications come in bursts, so it is looked up once per wake-up, not
	// once per notification.
	ownLUID    atomic.Uint64
	closeOnce  sync.Once
	closeErr   error
	interfaces *winipcfg.InterfaceChangeCallback
	addresses  *winipcfg.UnicastAddressChangeCallback
	routes     *winipcfg.RouteChangeCallback
}

func newNativeSource(_ time.Duration) (changeSource, error) {
	source := &notifySource{signals: make(chan struct{}, 1), done: make(chan struct{})}
	source.refreshOwnLUID()
	var err error
	source.interfaces, err = winipcfg.RegisterInterfaceChangeCallback(
		func(_ winipcfg.MibNotificationType, row *winipcfg.MibIPInterfaceRow) {
			source.notify(row.InterfaceLUID)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("registering interface change notifications: %w", err)
	}
	source.addresses, err = winipcfg.RegisterUnicastAddressChangeCallback(
		func(_ winipcfg.MibNotificationType, row *winipcfg.MibUnicastIPAddressRow) {
			source.notify(row.InterfaceLUID)
		},
	)
	if err != nil {
		_ = source.Close()

		return nil, fmt.Errorf("registering address change notifications: %w", err)
	}
	source.routes, err = winipcfg.RegisterRouteChangeCallback(
		func(_ winipcfg.MibNotificationType, row *winipcfg.MibIPforwardRow2) {
			source.notify(row.InterfaceLUID)
		},
	)
	if err != nil {
		_ = source.Close()

		return nil, fmt.Errorf("registering route change notifications: %w", err)
	}

	return source, nil
}

func (s *notifySource) refreshOwnLUID() {
	luid, _ := winadapter.LUID()
	s.ownLUID.Store(luid)
}

// notify runs on a goroutine winipcfg starts per notification; it never
// blocks, so unregistering does not wait on a reader.
func (s *notifySource) notify(luid winipcfg.LUID) {
	if own := s.ownLUID.Load(); own != 0 && uint64(luid) == own {
		return
	}
	select {
	case s.signals <- struct{}{}:
	default:
	}
}

func (s *notifySource) Wait(ctx context.Context) error {
	if s == nil {
		return errors.New("netwatch: notification source is closed")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return errors.New("netwatch: notification source is closed")
	case <-s.signals:
		// The adapter may have been created or recreated since the last
		// wake-up; a stale value only lets its own changes through once.
		s.refreshOwnLUID()

		return nil
	}
}

func (s *notifySource) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.done)
		var errs []error
		if s.interfaces != nil {
			errs = append(errs, s.interfaces.Unregister())
		}
		if s.addresses != nil {
			errs = append(errs, s.addresses.Unregister())
		}
		if s.routes != nil {
			errs = append(errs, s.routes.Unregister())
		}
		if err := errors.Join(errs...); err != nil {
			s.closeErr = fmt.Errorf("unregistering network notifications: %w", err)
		}
	})

	return s.closeErr
}

func defaultRouteTokens(excludedIndexes map[int]struct{}) ([]string, map[int]struct{}, error) {
	table, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, nil, fmt.Errorf("reading routing table: %w", err)
	}
	rows := make([]routeRow, 0, len(table))
	for i := range table {
		destination := table[i].DestinationPrefix.Prefix()
		if !destination.IsValid() {
			continue
		}
		rows = append(rows, routeRow{
			ipv6:    destination.Addr().Is6() && !destination.Addr().Is4In6(),
			bits:    destination.Bits(),
			index:   int(table[i].InterfaceIndex),
			nextHop: table[i].NextHop.Addr(),
		})
	}
	tokens, indexes := defaultRouteTokensFromRows(rows, excludedIndexes)

	return tokens, indexes, nil
}
