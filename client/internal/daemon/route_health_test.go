package daemon

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
)

func TestWatchRouteHealthSendsEachNewMeasuredSet(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	status := dataplane.SubnetRouterStatus{Sites: 2} // served, not measured yet
	read := func() dataplane.SubnetRouterStatus {
		mu.Lock()
		defer mu.Unlock()
		return status
	}
	set := func(next dataplane.SubnetRouterStatus) {
		mu.Lock()
		defer mu.Unlock()
		status = next
	}
	out := make(chan []controlplane.RouteSiteHealth)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go watchRouteHealth(ctx, read, 5*time.Millisecond, out)
	next := func() []controlplane.RouteSiteHealth {
		t.Helper()
		select {
		case health := <-out:
			return health
		case <-time.After(2 * time.Second):
			t.Fatal("no route health was sent")
			return nil
		}
	}
	measured := dataplane.SubnetRouterStatus{Sites: 2, Health: []dataplane.SiteHealth{
		{Ref: "uat", State: dataplane.SiteHealthOK, Code: dataplane.SiteCodeOK},
		{Ref: "prod", State: dataplane.SiteHealthFailed, Code: dataplane.SiteCodeForwardBlocked},
	}}
	set(measured)
	if got := next(); !slices.Equal(got, []controlplane.RouteSiteHealth{
		{Ref: "prod", State: controlplane.RouteHealthFailed, Code: "forward_blocked"},
		{Ref: "uat", State: controlplane.RouteHealthOK, Code: "ok"},
	}) {
		t.Fatalf("first set = %v", got)
	}
	// An unchanged set is not sent again; the stream repeats it itself.
	select {
	case health := <-out:
		t.Fatalf("an unchanged set was sent again: %v", health)
	case <-time.After(50 * time.Millisecond):
	}
	set(dataplane.SubnetRouterStatus{})
	if got := next(); got == nil || len(got) != 0 {
		t.Fatalf("serving nothing = %v, want the empty set", got)
	}
}

func TestRouteHealthOfSendsOnlyWhatCoreCanRead(t *testing.T) {
	t.Parallel()
	health, measured := routeHealthOf(dataplane.SubnetRouterStatus{Sites: 3, Health: []dataplane.SiteHealth{
		{Ref: "b", State: dataplane.SiteHealthFailed, Code: "Weird-Code"},
		{Ref: "a", State: dataplane.SiteHealthOK, Code: "ok"},
		{Ref: "a", State: dataplane.SiteHealthOK, Code: "ok"},
		{Ref: "", State: dataplane.SiteHealthOK, Code: "ok"},
	}})
	if !measured || !slices.Equal(health, []controlplane.RouteSiteHealth{
		{Ref: "a", State: controlplane.RouteHealthOK, Code: "ok"},
		{Ref: "b", State: controlplane.RouteHealthFailed, Code: "unknown"},
	}) {
		t.Fatalf("routeHealthOf() = %v, %t", health, measured)
	}
}
