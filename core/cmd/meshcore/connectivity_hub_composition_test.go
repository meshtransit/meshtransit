package main

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/platform/config"
)

type hubStoreFixture struct{}

func (hubStoreFixture) LoadConnectivity(context.Context, []mapsession.ConnectivityKey) ([]mapsession.Connectivity, error) {
	return nil, nil
}

type hubFeedFixture struct{}

func (hubFeedFixture) WatchNetwork(network.ID) (<-chan mapsession.ConnectivityChanged, func(), error) {
	return nil, nil, nil
}

func TestComposeConnectivityHubFollowsTheSwitch(t *testing.T) {
	t.Parallel()

	feed := hubFeedFixture{}
	off := config.ControlMapConfig{ReconcileInterval: 30 * time.Second, CoordinationTimeout: time.Second}
	hub, watcher, collector, err := composeConnectivityHub(off, hubStoreFixture{}, feed)
	if err != nil || hub != nil || collector != nil || watcher != feed {
		t.Fatalf("switched off = (%v, %v, %v, %v), want the feed alone", hub, watcher, collector, err)
	}
	on := off
	on.SharedConnectivity = true
	hub, watcher, collector, err = composeConnectivityHub(on, hubStoreFixture{}, feed)
	if err != nil || hub == nil || watcher != mapsession.ConnectivityWatcher(hub) || collector == nil {
		t.Fatalf("switched on = (%v, %v, %v, %v), want the hub", hub, watcher, collector, err)
	}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(collector)
	if families, err := registry.Gather(); err != nil || len(families) != 5 {
		t.Fatalf("Gather() = %d families, %v", len(families), err)
	}
	if _, _, _, err := composeConnectivityHub(on, nil, feed); err == nil {
		t.Fatal("composeConnectivityHub() accepted a missing store")
	}
}
