package daemon

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/cloudaddr"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/pathdiscovery"
)

type fakeCloud struct {
	mu        sync.Mutex
	addresses []netip.Addr
	network   int
	changes   chan struct{}
}

func (c *fakeCloud) Run(ctx context.Context) { <-ctx.Done() }

func (c *fakeCloud) Addresses() []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]netip.Addr(nil), c.addresses...)
}

func (c *fakeCloud) Changes() <-chan struct{} { return c.changes }

func (c *fakeCloud) NetworkChanged() {
	c.mu.Lock()
	c.network++
	c.mu.Unlock()
}

func (c *fakeCloud) Status() cloudaddr.Status {
	return cloudaddr.Status{State: cloudaddr.StateReady, Platform: cloudaddr.PlatformAWS, Addresses: c.Addresses()}
}

func (c *fakeCloud) set(addresses ...netip.Addr) {
	c.mu.Lock()
	c.addresses = addresses
	c.mu.Unlock()
	select {
	case c.changes <- struct{}{}:
	default:
	}
}

func TestEndpointRefreshPublishesCloudAddresses(t *testing.T) {
	t.Parallel()
	discoverer := &refreshDiscoverer{calls: make(chan struct{}, 4)}
	cloud := &fakeCloud{changes: make(chan struct{}, 1)}
	networkChanges := make(chan struct{}, 1)
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return time.Hour },
		networkChanges:       networkChanges,
		cloud:                cloud,
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- service.runEndpointRefresh(ctx, 15, discoverer, requests, updates) }()
	requests <- endpointRefreshRequest{active: true, socket: pathdiscovery.Socket{Port: 41641, Generation: 1}}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("no initial endpoint update")
	}

	public := netip.MustParseAddr("18.142.253.199")
	cloud.set(public)
	select {
	case update := <-updates:
		if !hasSource(update.Candidates, netip.AddrPortFrom(public, 41641), pathdiscovery.SourceConfigured) {
			t.Fatalf("candidates %v", update.Candidates.Candidates())
		}
	case <-time.After(time.Second):
		t.Fatal("the cloud address was not published")
	}
	if status := service.cloudStatus(); status.State != cloudaddr.StateReady || status.Platform != "aws" || len(status.Addresses) != 1 {
		t.Fatalf("status %+v", status)
	}

	networkChanges <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for {
		cloud.mu.Lock()
		network := cloud.network
		cloud.mu.Unlock()
		if network == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the network change did not reach the cloud watcher")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() = %v", err)
	}
}

func TestCloudStatusWithoutWatcher(t *testing.T) {
	t.Parallel()
	service := &Service{}
	if status := service.cloudStatus(); status.State != CloudOff {
		t.Fatalf("status %+v", status)
	}
	if service.cloudCandidates(41641).Len() != 0 {
		t.Fatal("candidates without a watcher")
	}
}
