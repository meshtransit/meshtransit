// Package netwatch reports meaningful host network changes without exposing
// interface addresses or routing details to consumers.
package netwatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultDebounceInterval = 750 * time.Millisecond
	defaultPollingInterval  = 5 * time.Second
)

// Options configures the bounded host network monitor.
type Options struct {
	Logger             *slog.Logger
	ExcludedInterfaces []string
}

// Monitor coalesces host network notifications into meaningful change events.
type Monitor struct {
	logger          *slog.Logger
	events          chan struct{}
	excluded        map[string]struct{}
	last            networkSnapshot
	snapshot        snapshotter
	newNativeSource sourceFactory
	debounce        time.Duration
	pollInterval    time.Duration
	started         atomic.Bool
}

type networkSnapshot struct {
	tokens []string
}

type snapshotter func(map[string]struct{}) (networkSnapshot, error)

type sourceFactory func(time.Duration) (changeSource, error)

type changeSource interface {
	Wait(context.Context) error
	Close() error
}

// New validates the initial host state and creates a monitor. Interface names
// in ExcludedInterfaces are omitted from both address and route comparisons.
func New(options Options) (*Monitor, error) {
	excluded := make(map[string]struct{}, len(options.ExcludedInterfaces))
	for _, interfaceName := range options.ExcludedInterfaces {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return nil, errors.New("netwatch: excluded interface name is empty")
		}
		excluded[interfaceName] = struct{}{}
	}

	initial, err := readNetworkSnapshot(excluded)
	if err != nil {
		return nil, fmt.Errorf("netwatch: reading initial network state: %w", err)
	}

	return &Monitor{
		logger:          options.Logger,
		events:          make(chan struct{}, 1),
		excluded:        excluded,
		last:            initial,
		snapshot:        readNetworkSnapshot,
		newNativeSource: newNativeSource,
		debounce:        defaultDebounceInterval,
		pollInterval:    defaultPollingInterval,
	}, nil
}

// Events returns a bounded channel that coalesces unread network changes.
func (m *Monitor) Events() <-chan struct{} {
	if m == nil {
		return nil
	}

	return m.events
}

// Run observes host network state until ctx is cancelled. A Monitor may only
// be run once.
func (m *Monitor) Run(ctx context.Context) error {
	if m == nil || m.snapshot == nil || m.newNativeSource == nil || m.events == nil {
		return errors.New("netwatch: monitor is not initialized")
	}
	if !m.started.CompareAndSwap(false, true) {
		return errors.New("netwatch: monitor is already running")
	}

	source, err := m.newNativeSource(m.pollInterval)
	if err != nil {
		m.logFallback("native network notifications unavailable", err)
		source = newPollingSource(m.pollInterval)
	}
	defer func() { m.closeSource(source) }()
	changed, err := m.sample()
	if err != nil {
		m.logFallback("initial network state reconciliation failed", err)
		m.closeSource(source)
		source = newPollingSource(m.pollInterval)
	} else if changed {
		m.offerEvent()
	}

	for {
		if err := source.Wait(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			m.logFallback("network notification source failed", err)
			m.closeSource(source)
			source = newPollingSource(m.pollInterval)
			continue
		}
		if err := waitFor(ctx, m.debounce); err != nil {
			return err
		}
		changed, err := m.sample()
		if err != nil {
			m.logFallback("network state sampling failed", err)
			m.closeSource(source)
			source = newPollingSource(m.pollInterval)
			continue
		}
		if changed {
			m.offerEvent()
		}
	}
}

func (m *Monitor) sample() (bool, error) {
	current, err := m.snapshot(m.excluded)
	if err != nil {
		return false, err
	}
	if slices.Equal(m.last.tokens, current.tokens) {
		return false, nil
	}
	m.last = current

	return true, nil
}

func (m *Monitor) offerEvent() {
	select {
	case m.events <- struct{}{}:
	default:
	}
}

func (m *Monitor) closeSource(source changeSource) {
	if source == nil {
		return
	}
	if err := source.Close(); err != nil && m.logger != nil {
		m.logger.Warn("closing network notification source failed", "error", err)
	}
}

func (m *Monitor) logFallback(message string, err error) {
	if m.logger != nil {
		m.logger.Warn(message, "error", err, "fallback", "polling")
	}
}

// ignoredInterface reports whether an interface takes no part in the host's
// network identity: a named exclusion, or on platforms whose tunnel names the
// kernel assigns (macOS utunN), any point-to-point interface.
func ignoredInterface(networkInterface net.Interface, excluded map[string]struct{}) bool {
	if _, skip := excluded[networkInterface.Name]; skip {
		return true
	}
	return ignorePointToPoint && networkInterface.Flags&net.FlagPointToPoint != 0
}

func readNetworkSnapshot(excluded map[string]struct{}) (networkSnapshot, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return networkSnapshot{}, fmt.Errorf("listing interfaces: %w", err)
	}
	excludedIndexes := make(map[int]struct{}, len(excluded))
	for _, networkInterface := range interfaces {
		if ignoredInterface(networkInterface, excluded) {
			excludedIndexes[networkInterface.Index] = struct{}{}
		}
	}
	routeTokens, defaultRouteIndexes, err := defaultRouteTokens(excludedIndexes)
	if err != nil {
		return networkSnapshot{}, fmt.Errorf("listing default routes: %w", err)
	}
	tokens := make([]string, 0, len(routeTokens)+(len(interfaces)*2))
	tokens = append(tokens, routeTokens...)
	for _, networkInterface := range interfaces {
		if ignoredInterface(networkInterface, excluded) {
			continue
		}
		if networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := usableInterfaceAddresses(networkInterface)
		if err != nil {
			return networkSnapshot{}, err
		}
		_, carriesDefaultRoute := defaultRouteIndexes[networkInterface.Index]
		isUp := networkInterface.Flags&net.FlagUp != 0
		hasUsablePath := len(addresses) != 0 || carriesDefaultRoute
		if !isUp || !hasUsablePath {
			continue
		}
		interfaceToken := "interface|" + strconv.Itoa(networkInterface.Index) + "|" +
			strconv.Quote(networkInterface.Name)
		tokens = append(tokens, interfaceToken)
		for _, address := range addresses {
			tokens = append(tokens, interfaceToken+"|address|"+address)
		}
	}
	sort.Strings(tokens)

	return networkSnapshot{tokens: tokens}, nil
}

func usableInterfaceAddresses(networkInterface net.Interface) ([]string, error) {
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("listing addresses for interface %q: %w", networkInterface.Name, err)
	}
	usable := make([]string, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if !isUsableAddress(ip) {
			continue
		}
		bits := prefix.Bits()
		if prefix.Addr().Is4In6() {
			if bits < 96 {
				continue
			}
			bits -= 96
		}
		canonical := netip.PrefixFrom(ip, bits)
		if !canonical.IsValid() {
			continue
		}
		usable = append(usable, canonical.String())
	}
	sort.Strings(usable)

	return usable, nil
}

func isUsableAddress(address netip.Addr) bool {
	return address.IsValid() &&
		address.IsGlobalUnicast() &&
		!address.IsLoopback() &&
		!address.IsLinkLocalUnicast() &&
		!address.IsLinkLocalMulticast() &&
		!address.IsMulticast() &&
		!address.IsUnspecified()
}

func waitFor(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
